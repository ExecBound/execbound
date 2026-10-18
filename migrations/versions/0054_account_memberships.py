"""Account authentication independent of workspace principals and their authority."""

import re

from alembic import op
from sqlalchemy import text

revision = "0054_account_memberships"
down_revision = "0053_persistent_community"
branch_labels = None
depends_on = None

ACCOUNT = "nullif((SELECT current_setting('execbound.account_id',true)),'')::uuid"
TENANT = "nullif((SELECT current_setting('execbound.tenant_id',true)),'')::uuid"
TABLES = (
    "user_accounts",
    "user_passwords",
    "workspace_memberships",
    "user_identities",
    "user_factors",
    "user_passkeys",
    "community_allocations",
    "account_login_proofs",
    "account_sessions",
    "account_provider_links",
    "user_security_events",
)

LOGIN = """
CREATE FUNCTION execbound.account_lock(p_account uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
BEGIN
    IF p_account IS DISTINCT FROM nullif(current_setting('execbound.account_id',true),'')::uuid
        THEN RAISE EXCEPTION 'INVALID_ACCOUNT'; END IF;
    PERFORM 1 FROM execbound.user_accounts WHERE account_id=p_account FOR UPDATE;
END $$;
CREATE FUNCTION execbound.account_login_credential(p_account uuid,p_version bigint,
    p_principal uuid,p_credential uuid,p_hash text,p_method text,p_now timestamptz,
    p_expires timestamptz) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    a execbound.user_accounts; k text;
BEGIN
    PERFORM set_config('execbound.account_id',p_account::text,true);
    SELECT * INTO a FROM execbound.user_accounts WHERE account_id=p_account FOR UPDATE;
    IF a.account_id IS NULL OR NOT a.active OR a.version<>p_version OR NOT EXISTS(
        SELECT 1 FROM execbound.workspace_memberships WHERE account_id=p_account
        AND tenant_id=t AND principal_id=p_principal AND active)
        THEN RAISE EXCEPTION 'INVALID_ACCOUNT'; END IF;
    k := execbound.sign_in_credential(p_principal,p_credential,p_hash,p_method,p_now,p_expires);
    INSERT INTO execbound.account_login_proofs(account_id,tenant_id,credential_id,version,method)
        VALUES(p_account,t,p_credential,p_version,p_method);
    RETURN k;
END $$;
CREATE FUNCTION execbound.account_session_open(p_credential uuid,p_session uuid,p_hash text,
    p_now timestamptz) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    proof execbound.account_login_proofs; a execbound.user_accounts;
BEGIN
    SELECT * INTO proof FROM execbound.account_login_proofs WHERE tenant_id=t
        AND credential_id=p_credential;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM set_config('execbound.account_id',proof.account_id::text,true);
    SELECT * INTO a FROM execbound.user_accounts WHERE account_id=proof.account_id FOR UPDATE;
    IF NOT a.active OR a.version<>proof.version OR p_hash !~ '^[0-9a-f]{64}$'
        OR abs(extract(epoch FROM (p_now-now())))>300
        OR NOT EXISTS(SELECT 1 FROM execbound.credentials WHERE tenant_id=t
            AND credential_id=p_credential AND revoked_at IS NULL AND expires_at>p_now)
        THEN RAISE EXCEPTION 'INVALID_ACCOUNT'; END IF;
    INSERT INTO execbound.account_sessions(account_id,session_id,token_hash,created_at,
        expires_at,absolute_expires_at,version,method,current_tenant,current_session)
        VALUES(a.account_id,p_session,p_hash,p_now,p_now+interval '15 minutes',
            p_now+interval '8 hours',a.version,proof.method,t,p_session);
    RETURN a.account_id;
END $$;
CREATE FUNCTION execbound.account_session_touch(p_session uuid,p_now timestamptz) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
BEGIN
    UPDATE execbound.account_sessions x SET expires_at=least(p_now+interval '15 minutes',
        absolute_expires_at),label=coalesce((SELECT label FROM execbound.human_sessions h
            WHERE h.tenant_id=x.current_tenant AND h.session_id=x.current_session),'Other')
        WHERE account_id=nullif(current_setting('execbound.account_id',true),'')::uuid
        AND session_id=p_session AND revoked_at IS NULL AND expires_at>p_now
        AND created_at<=p_now;
END $$;
CREATE FUNCTION execbound.account_session_revoke(p_session uuid,p_now timestamptz,p_others boolean)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
DECLARE
    a uuid := nullif(current_setting('execbound.account_id',true),'')::uuid;
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    s execbound.human_sessions; ended integer;
BEGIN
    SELECT * INTO s FROM execbound.human_sessions WHERE tenant_id=t AND session_id=p_session;
    IF a IS NULL OR s.account_id IS DISTINCT FROM a OR s.revoked_at IS NOT NULL
        OR s.expires_at<=p_now OR NOT EXISTS(SELECT 1 FROM execbound.account_sessions x
            JOIN execbound.user_accounts u USING(account_id) WHERE x.account_id=a
            AND x.session_id=s.account_session_id AND x.current_session=p_session
            AND x.current_tenant=t AND x.revoked_at IS NULL AND x.expires_at>p_now
            AND u.active AND u.version=x.version) THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    UPDATE execbound.account_sessions SET revoked_at=p_now WHERE account_id=a
        AND revoked_at IS NULL AND expires_at>p_now AND
        (CASE WHEN p_others THEN session_id<>s.account_session_id
            ELSE session_id=s.account_session_id END);
    GET DIAGNOSTICS ended=ROW_COUNT;
    IF p_others THEN
        UPDATE execbound.user_accounts SET version=version+1 WHERE account_id=a;
        UPDATE execbound.account_sessions SET version=(SELECT version FROM execbound.user_accounts
            WHERE account_id=a) WHERE account_id=a AND session_id=s.account_session_id;
    END IF;
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        VALUES(a,CASE WHEN p_others THEN 'other_devices_signed_out' ELSE 'signed_out' END,p_now);
    RETURN ended;
END $$;
"""

ADOPT = """
CREATE FUNCTION execbound.account_adopt(p_principal uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    a uuid; person execbound.principals;
    old_account text := coalesce(current_setting('execbound.account_id',true),'');
BEGIN
    -- Serializes only this legacy principal's first adoption. Existing accounts are
    -- never locked here, so a tenant-local bootstrap cannot invert account lock order.
    PERFORM 1 FROM execbound.principals WHERE tenant_id=t AND principal_id=p_principal
        FOR UPDATE;
    SELECT account_id INTO a FROM execbound.workspace_memberships
        WHERE tenant_id=t AND principal_id=p_principal;
    IF FOUND THEN RETURN a; END IF;
    SELECT * INTO person FROM execbound.principals WHERE tenant_id=t
        AND principal_id=p_principal AND kind IN ('ADMIN','HUMAN_APPROVER');
    IF person.email IS NULL OR (NOT EXISTS(SELECT 1 FROM execbound.principal_passwords
        WHERE tenant_id=t AND principal_id=p_principal) AND NOT EXISTS(
        SELECT 1 FROM execbound.principal_identities WHERE tenant_id=t
        AND principal_id=p_principal AND revoked_at IS NULL)) THEN RETURN NULL; END IF;
    -- An existing email is never an instruction to join its account. Only an explicit
    -- authenticated invitation can add another membership. The unique key fails closed.
    a := gen_random_uuid();
    PERFORM set_config('execbound.account_id',a::text,true);
    INSERT INTO execbound.user_accounts(account_id,email) VALUES(a,person.email);
    UPDATE execbound.user_accounts SET email_verified_at=(SELECT min(created_at)
        FROM execbound.principal_identities WHERE tenant_id=t AND principal_id=p_principal
        AND email=person.email AND revoked_at IS NULL) WHERE account_id=a;
    INSERT INTO execbound.workspace_memberships(account_id,tenant_id,principal_id,legacy_access)
        VALUES(a,t,p_principal,true);
    INSERT INTO execbound.user_passwords(account_id,algorithm,n,r,p,dklen,salt,hash,
        created_at,updated_at)
        SELECT a,algorithm,n,r,p,dklen,salt,hash,created_at,updated_at
        FROM execbound.principal_passwords WHERE tenant_id=t AND principal_id=p_principal;
    INSERT INTO execbound.user_identities(account_id,provider,subject,email,display_name,
        created_at,last_sign_in_at,revoked_at)
        SELECT a,provider,subject,email,display_name,created_at,last_sign_in_at,revoked_at
        FROM execbound.principal_identities WHERE tenant_id=t AND principal_id=p_principal;
    INSERT INTO execbound.user_factors(account_id,tenant_id,principal_id,sealed,key_id,
        enabled_at,version,last_step,recovery_hashes,failures,locked_until)
        SELECT a,tenant_id,principal_id,sealed,key_id,enabled_at,version,last_step,
        recovery_hashes,failures,locked_until FROM execbound.account_factors
        WHERE tenant_id=t AND principal_id=p_principal;
    INSERT INTO execbound.user_passkeys(account_id,tenant_id,principal_id,credential_id,
        public_key,sign_count,created_at)
        SELECT a,tenant_id,principal_id,credential_id,public_key,sign_count,created_at
        FROM execbound.account_passkeys WHERE tenant_id=t AND principal_id=p_principal;
    UPDATE execbound.human_sessions SET account_version=1,membership_version=1
        WHERE tenant_id=t AND principal_id=p_principal;
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        SELECT a,CASE kind
            WHEN 'account_security.factor_enabled' THEN 'enable'
            WHEN 'account_security.factor_disabled' THEN 'disable'
            WHEN 'account_security.recovery_replaced' THEN 'recovery'
            WHEN 'account_security.passkey_added' THEN 'passkey_register'
            WHEN 'account_security.passkey_removed' THEN 'passkey_remove'
            WHEN 'password.changed' THEN 'password' END,occurred_at
        FROM execbound.audit_events WHERE tenant_id=t AND actor_id=p_principal
            AND kind IN ('account_security.factor_enabled','account_security.factor_disabled',
                'account_security.recovery_replaced','account_security.passkey_added',
                'account_security.passkey_removed','password.changed');
    PERFORM set_config('execbound.account_id',old_account,true);
    RETURN a;
END $$;
REVOKE ALL ON FUNCTION execbound.account_adopt(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION execbound.account_adopt(uuid) TO execbound_app;
"""

ADMIN_GUARD = """
    IF EXISTS(SELECT 1 FROM execbound.workspace_memberships
        WHERE tenant_id=v_tenant AND principal_id=p_principal) THEN
        RAISE EXCEPTION 'ACCOUNT_OWNER_REQUIRED';
    END IF;
"""

SWITCH = """
CREATE FUNCTION execbound.account_switch(p_previous uuid,p_destination uuid,p_next uuid,
    p_credential uuid,p_token_hash text,p_csrf_hash text,p_credential_hash text,p_now timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
DECLARE
    a uuid := nullif(current_setting('execbound.account_id',true),'')::uuid;
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    old execbound.human_sessions; x execbound.account_sessions;
    member execbound.workspace_memberships; k text; expiry timestamptz;
BEGIN
    SELECT * INTO old FROM execbound.human_sessions WHERE tenant_id=t AND session_id=p_previous;
    SELECT * INTO x FROM execbound.account_sessions WHERE account_id=a
        AND session_id=old.account_session_id FOR UPDATE;
    IF old.account_id IS DISTINCT FROM a OR old.revoked_at IS NOT NULL OR old.expires_at<=p_now
        OR x.session_id IS NULL OR x.revoked_at IS NOT NULL OR x.expires_at<=p_now
        OR x.current_session<>p_previous OR x.current_tenant<>t OR NOT EXISTS(
            SELECT 1 FROM execbound.user_accounts
            WHERE account_id=a AND active AND version=x.version)
        THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    SELECT m.* INTO member FROM execbound.workspace_memberships m
        JOIN execbound.user_accounts u USING(account_id)
        WHERE m.account_id=a AND m.tenant_id=p_destination AND m.active
          AND (m.legacy_access OR u.email_verified_at IS NOT NULL);
    IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_MEMBERSHIP'; END IF;
    IF p_token_hash !~ '^[0-9a-f]{64}$' OR p_csrf_hash !~ '^[0-9a-f]{64}$'
        OR abs(extract(epoch FROM (p_now-now())))>300
        THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    PERFORM set_config('execbound.tenant_id',p_destination::text,true);
    k := execbound.sign_in_credential(member.principal_id,p_credential,p_credential_hash,
        x.method,p_now,x.absolute_expires_at);
    k := execbound.access_effective_kind(member.principal_id);
    expiry := least(p_now+interval '15 minutes',x.absolute_expires_at);
    INSERT INTO execbound.human_sessions(tenant_id,session_id,principal_id,credential_id,kind,
        credential_expires_at,token_hash,csrf_hash,created_at,expires_at,label,
        account_id,account_session_id,account_version,membership_version)
        VALUES(p_destination,p_next,member.principal_id,p_credential,k,x.absolute_expires_at,
            p_token_hash,p_csrf_hash,p_now,expiry,old.label,a,x.session_id,x.version,member.version);
    UPDATE execbound.account_sessions SET current_tenant=p_destination,current_session=p_next,
        expires_at=expiry WHERE account_id=a AND session_id=x.session_id;
    -- The destination starts without assurance. Its current policy and the global
    -- factor require a new verification when the new session is loaded.
    PERFORM set_config('execbound.tenant_id',t::text,true);
    UPDATE execbound.human_sessions SET revoked_at=p_now
        WHERE tenant_id=t AND session_id=p_previous;
    PERFORM set_config('execbound.tenant_id',p_destination::text,true);
    RETURN jsonb_build_object('principal_id',member.principal_id,'kind',k,
        'expires_at',expiry,'credential_expires_at',x.absolute_expires_at);
END $$;
"""


def protect(table: str, expression: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY account_isolation ON execbound.{table} "
        f"USING({expression}) WITH CHECK({expression})"
    )
    op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC,execbound_app")
    op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")


def admin_guards(*, restore: bool = False) -> None:
    for name in (
        "admin_set_email",
        "admin_reset_password",
        "password_replace",
        "password_redeem",
        "identity_sign_in",
        "account_security_change",
    ):
        definition = (
            op.get_bind()
            .execute(
                text("""SELECT pg_get_functiondef(p.oid)
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='execbound' AND p.proname=:name"""),
                {"name": name},
            )
            .scalar_one()
        )
        guard = (
            ADMIN_GUARD.replace("p_principal", "v_principal")
            if name == "password_redeem"
            else ADMIN_GUARD
        )
        if name == "account_security_change":
            guard = ADMIN_GUARD.replace("v_tenant", "t").replace("p_principal", "s.principal_id")
        if restore:
            definition = definition.replace(guard, "")
        elif name == "password_redeem":
            marker = "v_principal := execbound.password_reset_check(p_reset, p_token_hash);"
            definition = definition.replace(marker, marker + guard, 1)
        elif name == "account_security_change":
            definition = definition.replace("    SELECT * INTO f", guard + "    SELECT * INTO f", 1)
        else:
            definition = definition.replace("BEGIN\n", "BEGIN\n" + guard, 1)
        op.execute(definition)


def backfill_ownership(connection) -> None:
    """Retain ambiguous claims for operator resolution; never infer an owner from a role."""
    connection.execute(
        text("""
        INSERT INTO execbound.community_allocations(tenant_id,claimant_principal_id,
            account_id,state)
        SELECT s.tenant_id,c.principal_id,m.account_id,
            CASE WHEN m.account_id IS NULL THEN 'unresolved' ELSE 'consumed' END
        FROM execbound.onboarding_slots s
        LEFT JOIN LATERAL (
            SELECT CASE WHEN count(DISTINCT e.payload->>'principal_id')=1
                AND bool_and(COALESCE(e.payload->>'slot'=s.slot::text
                    AND e.payload->>'principal_id' ~
                    '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false))
                THEN min(e.payload->>'principal_id')::uuid END AS principal_id
            FROM execbound.audit_events e WHERE e.tenant_id=s.tenant_id
                AND e.kind='tenant.claimed'
        ) c ON true
        LEFT JOIN execbound.workspace_memberships m ON m.tenant_id=s.tenant_id
            AND m.principal_id=c.principal_id
        WHERE s.claimed_at IS NOT NULL
        ON CONFLICT(tenant_id) DO NOTHING
    """)
    )


def global_security_function() -> None:
    """Reuse the pinned security transition rules with independent account storage."""
    source = (
        op.get_bind()
        .execute(
            text("""SELECT p.prosrc FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='execbound' AND p.proname='account_security_change'""")
        )
        .scalar_one()
    )
    source = source.replace("DECLARE", "DECLARE\n    v_account uuid;", 1)
    source = source.replace("execbound.account_factors", "execbound.user_factors")
    source = source.replace("execbound.account_passkeys", "execbound.user_passkeys")
    source = source.replace(
        "    SELECT * INTO f",
        """
    v_account := s.account_id;
    IF v_account IS NULL THEN
        SELECT m.account_id INTO v_account FROM execbound.workspace_memberships m
            WHERE m.tenant_id=t AND m.principal_id=s.principal_id AND m.active
            AND m.version=s.membership_version;
        IF v_account IS NULL OR p_operation NOT IN
            ('verify','fail','passkey_begin','passkey_consume','passkey_verify','rotate_session','policy')
            OR (p_operation IN ('passkey_begin','passkey_consume')
                AND p_data->>'kind' IS DISTINCT FROM 'authenticate')
            THEN RAISE EXCEPTION 'ACCOUNT_SIGN_IN_REQUIRED'; END IF;
    END IF;
    PERFORM set_config('execbound.account_id',v_account::text,true);
    IF s.account_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM execbound.account_sessions x
        JOIN execbound.user_accounts a USING(account_id)
        WHERE x.account_id=v_account AND x.session_id=s.account_session_id
        AND a.active AND a.version=x.version AND x.revoked_at IS NULL
        AND x.created_at<=p_now AND x.expires_at>p_now AND x.current_session=p_session
        AND x.current_tenant=t) THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    IF s.account_id IS NULL AND NOT EXISTS(SELECT 1 FROM execbound.user_accounts
        WHERE account_id=v_account AND active AND version=s.account_version)
        THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    SELECT * INTO f""",
        1,
    )
    source = re.sub(
        r"tenant_id=t AND\s+principal_id=s\.principal_id", "account_id=v_account", source
    )
    source = source.replace(
        "user_factors(tenant_id,principal_id,", "user_factors(account_id,tenant_id,principal_id,"
    )
    source = source.replace(
        "user_passkeys(tenant_id,principal_id,", "user_passkeys(account_id,tenant_id,principal_id,"
    )
    source = source.replace(
        "VALUES(t,s.principal_id,p_data", "VALUES(v_account,v_account,v_account,p_data"
    )
    source = source.replace(
        "public_key,sign_count,created_at)", "public_key,sign_count,created_at,binding_version)"
    ).replace(
        "(p_data->>'sign_count')::bigint,p_now);", "(p_data->>'sign_count')::bigint,p_now,2);"
    )
    source = source.replace("ON CONFLICT(tenant_id,principal_id)", "ON CONFLICT(account_id)")
    source = source.replace(
        "SET sealed=pending_sealed,key_id=pending_key,",
        "SET sealed=pending_sealed,key_id=pending_key,tenant_id=v_account,"
        "principal_id=v_account,binding_version=2,",
    )
    source = source.replace(
        "    ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;",
        """
    ELSIF p_operation IN ('link_begin','link_finish') THEN
        IF (f.enabled_at IS NOT NULL AND NOT fresh) OR
            NOT EXISTS(SELECT 1 FROM execbound.account_sessions x WHERE x.account_id=v_account
                AND x.session_id=s.account_session_id AND x.created_at>p_now-interval '5 minutes'
                AND x.created_at<=p_now) OR NOT EXISTS(
                    SELECT 1 FROM execbound.user_accounts WHERE account_id=v_account
                    AND email_verified_at IS NOT NULL)
            THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        IF p_operation='link_begin' THEN
            DELETE FROM execbound.account_provider_links WHERE account_id=v_account
                AND session_id=p_session;
            INSERT INTO execbound.account_provider_links(account_id,link_id,tenant_id,
                session_id,provider,state_hash,token_hash,created_at,expires_at)
                VALUES(v_account,(p_data->>'link')::uuid,t,p_session,p_data->>'provider',
                    p_data->>'state_hash',p_data->>'token_hash',p_now,p_now+interval '5 minutes');
        ELSE
            UPDATE execbound.account_provider_links SET consumed_at=p_now
                WHERE account_id=v_account AND link_id=(p_data->>'link')::uuid
                AND tenant_id=t AND session_id=p_session AND provider=p_data->>'provider'
                AND state_hash=p_data->>'state_hash' AND token_hash=p_data->>'token_hash'
                AND created_at<=p_now AND expires_at>p_now AND consumed_at IS NULL;
            IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM execbound.user_accounts
                WHERE account_id=v_account AND email=p_data->>'email')
                THEN RAISE EXCEPTION 'INVALID_LINK'; END IF;
            INSERT INTO execbound.user_identities(account_id,provider,subject,email,
                display_name,created_at,last_sign_in_at)
                VALUES(v_account,p_data->>'provider',p_data->>'subject',p_data->>'email',
                    p_data->>'display_name',p_now,p_now);
        END IF;
    ELSIF p_operation='password' THEN
        IF f.enabled_at IS NOT NULL AND NOT fresh THEN
            RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        UPDATE execbound.user_passwords SET algorithm=p_data->>'algorithm',
            n=(p_data->>'n')::integer,r=(p_data->>'r')::integer,p=(p_data->>'p')::integer,
            dklen=(p_data->>'dklen')::integer,salt=p_data->>'salt',hash=p_data->>'hash',
            updated_at=p_now WHERE account_id=v_account AND hash=p_data->>'expected_hash';
        IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_CURRENT'; END IF;
    ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;""",
    )
    # Account-scoped changes invalidate other personal sessions, including ones whose
    # selected workspace has an optional MFA policy. No tenant admin participates.
    before, after = source.rsplit("END", 1)
    source = (
        before
        + """
    IF p_operation IN ('enable','disable','recovery','passkey_register','passkey_remove',
        'password','link_finish') THEN
        UPDATE execbound.user_accounts SET version=version+1 WHERE account_id=v_account;
        UPDATE execbound.account_sessions SET version=(SELECT version
            FROM execbound.user_accounts WHERE account_id=v_account)
            WHERE account_id=v_account AND session_id=s.account_session_id;
        UPDATE execbound.account_sessions SET revoked_at=p_now
            WHERE account_id=v_account AND session_id<>s.account_session_id
            AND revoked_at IS NULL;
    END IF;
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        VALUES(v_account,p_operation,p_now);
END"""
        + after
    )
    op.execute(
        "CREATE FUNCTION execbound.user_security_change(p_session uuid,p_now timestamptz,"
        "p_operation text,p_data jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER "
        "SET search_path=pg_catalog,execbound AS $account$" + source + "$account$"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION execbound.user_security_change(uuid,timestamptz,text,jsonb) "
        "FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION execbound.user_security_change(uuid,timestamptz,text,jsonb) "
        "TO execbound_app"
    )


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.identity_providers ADD COLUMN require_sign_in boolean
            NOT NULL DEFAULT false;
        CREATE TABLE execbound.user_accounts(
            account_id uuid PRIMARY KEY, email text NOT NULL UNIQUE,
            email_verified_at timestamptz, active boolean NOT NULL DEFAULT true,
            version bigint NOT NULL DEFAULT 1 CHECK(version>0),
            created_at timestamptz NOT NULL DEFAULT now(),
            CHECK(email=lower(email) AND length(email) BETWEEN 3 AND 254)
        );
        CREATE TABLE execbound.workspace_memberships(
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
            active boolean NOT NULL DEFAULT true,
            legacy_access boolean NOT NULL DEFAULT false,
            version bigint NOT NULL DEFAULT 1 CHECK(version>0),
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY(account_id,tenant_id), UNIQUE(tenant_id,principal_id),
            FOREIGN KEY(tenant_id,principal_id) REFERENCES execbound.principals
        );
        CREATE TABLE execbound.user_passwords(
            account_id uuid PRIMARY KEY REFERENCES execbound.user_accounts,
            algorithm text NOT NULL CHECK(algorithm='scrypt'),
            n integer NOT NULL CHECK(n BETWEEN 16384 AND 1048576 AND (n & (n-1))=0),
            r integer NOT NULL CHECK(r BETWEEN 1 AND 32),
            p integer NOT NULL CHECK(p BETWEEN 1 AND 16),
            dklen integer NOT NULL CHECK(dklen BETWEEN 32 AND 64),
            salt text NOT NULL CHECK(salt ~ '^[0-9a-f]{32}$'),
            hash text NOT NULL CHECK(hash ~ '^[0-9a-f]+$' AND length(hash)=dklen*2),
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL CHECK(updated_at>=created_at)
        );
        CREATE TABLE execbound.user_identities(
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            provider text NOT NULL CHECK(provider IN ('google','github')),
            subject text NOT NULL CHECK(length(subject) BETWEEN 1 AND 255),
            email text,display_name text,created_at timestamptz NOT NULL,
            last_sign_in_at timestamptz,revoked_at timestamptz,
            PRIMARY KEY(provider,subject)
        );
        CREATE INDEX user_identities_account ON execbound.user_identities(account_id);
        -- tenant_id/principal_id in these two tables are immutable legacy cryptographic
        -- bindings, NOT membership or authority. No foreign key to the old workspace.
        CREATE TABLE execbound.user_factors(
            LIKE execbound.account_factors INCLUDING DEFAULTS INCLUDING CONSTRAINTS,
            account_id uuid PRIMARY KEY REFERENCES execbound.user_accounts,
            binding_version integer NOT NULL DEFAULT 1 CHECK(binding_version IN (1,2)),
            pending_tenant_id uuid,pending_principal_id uuid
        );
        CREATE TABLE execbound.user_passkeys(
            LIKE execbound.account_passkeys INCLUDING DEFAULTS INCLUDING CONSTRAINTS,
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            PRIMARY KEY(account_id,credential_id),UNIQUE(credential_id),
            binding_version integer NOT NULL DEFAULT 1 CHECK(binding_version IN (1,2))
        );
        CREATE TABLE execbound.community_allocations(
            tenant_id uuid PRIMARY KEY REFERENCES execbound.tenants,
            claimant_principal_id uuid,
            account_id uuid REFERENCES execbound.user_accounts,
            state text NOT NULL CHECK(state IN ('consumed','unresolved')),
            retained_at timestamptz NOT NULL DEFAULT now(),
            CHECK(state<>'consumed' OR account_id IS NOT NULL)
        );
        CREATE UNIQUE INDEX community_allocations_account
            ON execbound.community_allocations(account_id)
            WHERE state='consumed';
        CREATE INDEX community_allocations_account_lookup
            ON execbound.community_allocations(account_id);
        CREATE TABLE execbound.account_login_proofs(
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            tenant_id uuid NOT NULL,credential_id uuid NOT NULL,
            version bigint NOT NULL,
            method text NOT NULL CHECK(method IN ('password','google','github')),
            PRIMARY KEY(tenant_id,credential_id),
            FOREIGN KEY(tenant_id,credential_id) REFERENCES execbound.credentials
        );
        CREATE INDEX account_login_proofs_account ON execbound.account_login_proofs(account_id);
        CREATE TABLE execbound.account_sessions(
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            session_id uuid NOT NULL,token_hash text NOT NULL CHECK(token_hash ~ '^[0-9a-f]{64}$'),
            created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
            absolute_expires_at timestamptz NOT NULL,revoked_at timestamptz,
            version bigint NOT NULL,
            method text NOT NULL CHECK(method IN ('password','google','github')),
            current_tenant uuid,current_session uuid,label text NOT NULL DEFAULT 'Other',
            PRIMARY KEY(account_id,session_id),UNIQUE(session_id),
            CHECK(created_at<expires_at AND expires_at<=absolute_expires_at)
        );
        CREATE TABLE execbound.account_provider_links(
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            link_id uuid NOT NULL,tenant_id uuid NOT NULL,session_id uuid NOT NULL,
            provider text NOT NULL CHECK(provider IN ('google','github')),
            state_hash text NOT NULL CHECK(state_hash ~ '^[0-9a-f]{64}$'),
            token_hash text NOT NULL CHECK(token_hash ~ '^[0-9a-f]{64}$'),
            created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
            consumed_at timestamptz,
            PRIMARY KEY(account_id,link_id),
            FOREIGN KEY(tenant_id,session_id) REFERENCES execbound.human_sessions,
            CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
        );
        CREATE TABLE execbound.user_security_events(
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            event_id uuid NOT NULL DEFAULT gen_random_uuid(),kind text NOT NULL,
            occurred_at timestamptz NOT NULL,
            PRIMARY KEY(account_id,event_id),CHECK(length(kind) BETWEEN 1 AND 64)
        );
        CREATE INDEX account_provider_links_session
            ON execbound.account_provider_links(tenant_id,session_id);
        CREATE INDEX user_security_events_time
            ON execbound.user_security_events(account_id,occurred_at);
        ALTER TABLE execbound.human_sessions ADD COLUMN account_id uuid,
            ADD COLUMN account_session_id uuid,
            ADD COLUMN account_version bigint,
            ADD COLUMN membership_version bigint,
            ADD FOREIGN KEY(account_id,account_session_id)
                REFERENCES execbound.account_sessions(account_id,session_id),
            ADD CHECK((account_id IS NULL)=(account_session_id IS NULL)),
            ADD CHECK(account_id IS NULL OR membership_version IS NOT NULL);
        CREATE INDEX human_sessions_account
            ON execbound.human_sessions(account_id,account_session_id);
    """)
    for table in TABLES:
        expression = f"account_id={ACCOUNT}"
        if table in {"workspace_memberships", "community_allocations", "account_login_proofs"}:
            expression += f" OR tenant_id={TENANT}"
        protect(table, expression)
    op.execute(
        "CREATE POLICY account_email_lookup ON execbound.user_accounts FOR SELECT "
        "USING(email=(SELECT current_setting('execbound.sign_in_email',true)))"
    )
    op.execute(
        "CREATE POLICY account_subject_lookup ON execbound.user_identities FOR SELECT "
        "USING(provider=(SELECT current_setting('execbound.sign_in_provider',true)) AND "
        "subject=(SELECT current_setting('execbound.sign_in_subject',true)))"
    )
    op.execute(ADOPT)
    op.execute(LOGIN)
    op.execute(SWITCH)
    global_security_function()
    for signature in (
        "account_switch(uuid,uuid,uuid,uuid,text,text,text,timestamptz)",
        "account_lock(uuid)",
        "account_login_credential(uuid,bigint,uuid,uuid,text,text,timestamptz,timestamptz)",
        "account_session_open(uuid,uuid,text,timestamptz)",
        "account_session_touch(uuid,timestamptz)",
        "account_session_revoke(uuid,timestamptz,boolean)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")
    # Owner migration reads every tenant explicitly, lifting FORCE only for this
    # transactional backfill; the runtime role never acquires migration privileges.
    op.execute("ALTER TABLE execbound.principals NO FORCE ROW LEVEL SECURITY")
    people = (
        op.get_bind()
        .execute(
            text(
                "SELECT tenant_id,principal_id FROM execbound.principals "
                "WHERE email IS NOT NULL AND kind IN ('ADMIN','HUMAN_APPROVER') "
                "ORDER BY tenant_id,principal_id"
            )
        )
        .all()
    )
    op.execute("ALTER TABLE execbound.principals FORCE ROW LEVEL SECURITY")
    for tenant, principal in people:
        op.get_bind().execute(
            text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)}
        )
        op.get_bind().execute(text("SELECT execbound.account_adopt(:p)"), {"p": principal})
    op.execute("SELECT set_config('execbound.tenant_id','',true)")
    for table in (
        "onboarding_slots",
        "audit_events",
        "workspace_memberships",
        "community_allocations",
        "password_resets",
        "account_factors",
        "passkey_challenges",
    ):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    backfill_ownership(op.get_bind())
    op.execute("""
        UPDATE execbound.password_resets SET revoked_at=greatest(now(),created_at)
            WHERE redeemed_at IS NULL AND revoked_at IS NULL;
        UPDATE execbound.account_factors SET pending_sealed=NULL,pending_key=NULL,
            pending_session=NULL,pending_expires=NULL;
        UPDATE execbound.passkey_challenges SET used_at=now() WHERE used_at IS NULL;
    """)
    for table in (
        "onboarding_slots",
        "audit_events",
        "workspace_memberships",
        "community_allocations",
        "password_resets",
        "account_factors",
        "passkey_challenges",
    ):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    admin_guards()


def downgrade() -> None:
    op.execute("ALTER TABLE execbound.user_accounts NO FORCE ROW LEVEL SECURITY")
    if op.get_bind().execute(text("SELECT 1 FROM execbound.user_accounts LIMIT 1")).scalar():
        raise RuntimeError("Account data requires a verified full restore; lossy downgrade refused")
    admin_guards(restore=True)
    op.execute("ALTER TABLE execbound.identity_providers DROP COLUMN require_sign_in")
    op.execute("DROP FUNCTION execbound.account_adopt(uuid)")
    op.execute(
        "DROP FUNCTION execbound.account_switch(uuid,uuid,uuid,uuid,text,text,text,timestamptz)"
    )
    op.execute("DROP FUNCTION execbound.user_security_change(uuid,timestamptz,text,jsonb)")
    op.execute("DROP FUNCTION execbound.account_lock(uuid)")
    op.execute(
        "DROP FUNCTION execbound.account_login_credential"
        "(uuid,bigint,uuid,uuid,text,text,timestamptz,timestamptz)"
    )
    op.execute("DROP FUNCTION execbound.account_session_open(uuid,uuid,text,timestamptz)")
    op.execute("DROP FUNCTION execbound.account_session_touch(uuid,timestamptz)")
    op.execute("DROP FUNCTION execbound.account_session_revoke(uuid,timestamptz,boolean)")
    op.execute(
        "ALTER TABLE execbound.human_sessions DROP COLUMN account_id, "
        "DROP COLUMN account_session_id, DROP COLUMN membership_version, "
        "DROP COLUMN account_version"
    )
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
