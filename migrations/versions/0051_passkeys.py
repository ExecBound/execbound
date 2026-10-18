"""Bound passkey challenges and credentials for human MFA."""

import importlib.util
from pathlib import Path

from alembic import op

revision = "0051_passkeys"
down_revision = "0050_account_security"
branch_labels = None
depends_on = None

PASSKEYS = """
    ELSIF p_operation='rotate_session' THEN
        IF NOT fresh THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        UPDATE execbound.human_sessions SET token_hash=p_data->>'token_hash',
            csrf_hash=p_data->>'csrf_hash' WHERE tenant_id=t AND session_id=p_session;
    ELSIF p_operation='passkey_begin' THEN
        IF f.enabled_at IS NULL OR (p_data->>'kind'='register' AND NOT fresh)
            THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        INSERT INTO execbound.passkey_challenges(tenant_id,session_id,kind,challenge,expires_at)
        VALUES(t,p_session,p_data->>'kind',p_data->>'challenge',p_now+interval '5 minutes')
        ON CONFLICT(tenant_id,session_id) DO UPDATE SET kind=excluded.kind,
            challenge=excluded.challenge,expires_at=excluded.expires_at,used_at=NULL;
    ELSIF p_operation='passkey_consume' THEN
        UPDATE execbound.passkey_challenges SET used_at=p_now WHERE tenant_id=t
            AND session_id=p_session AND kind=p_data->>'kind' AND used_at IS NULL
            AND expires_at>p_now;
        IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_CHALLENGE'; END IF;
    ELSIF p_operation='passkey_register' THEN
        IF NOT fresh OR f.enabled_at IS NULL THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        IF (SELECT count(*) FROM execbound.account_passkeys WHERE tenant_id=t
            AND principal_id=s.principal_id)>=5 THEN RAISE EXCEPTION 'FACTOR_LIMIT'; END IF;
        INSERT INTO execbound.account_passkeys(tenant_id,principal_id,credential_id,
            public_key,sign_count,created_at)
        VALUES(t,s.principal_id,p_data->>'credential_id',p_data->>'public_key',
            (p_data->>'sign_count')::bigint,p_now);
    ELSIF p_operation='passkey_verify' THEN
        IF f.enabled_at IS NULL OR f.locked_until>p_now THEN RAISE EXCEPTION
            'INVALID_FACTOR'; END IF;
        UPDATE execbound.account_passkeys SET sign_count=(p_data->>'sign_count')::bigint
            WHERE tenant_id=t AND principal_id=s.principal_id
            AND credential_id=p_data->>'credential_id';
        IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_FACTOR'; END IF;
        UPDATE execbound.account_factors SET failures=0,locked_until=NULL
            WHERE tenant_id=t AND principal_id=s.principal_id;
    ELSIF p_operation='passkey_remove' THEN
        IF NOT fresh THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        DELETE FROM execbound.account_passkeys WHERE tenant_id=t AND principal_id=s.principal_id
            AND credential_id=p_data->>'credential_id';
        IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_FACTOR'; END IF;
"""


def previous() -> str:
    spec = importlib.util.spec_from_file_location(
        "account_revision", Path(__file__).with_name("0050_account_security.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(module.CHANGE).replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)


def upgrade() -> None:
    op.execute("""
      CREATE TABLE execbound.account_passkeys(
        tenant_id uuid NOT NULL,principal_id uuid NOT NULL,credential_id text NOT NULL,
        public_key text NOT NULL,sign_count bigint NOT NULL CHECK(sign_count>=0),created_at
            timestamptz NOT NULL,
        PRIMARY KEY(tenant_id,credential_id),FOREIGN KEY(tenant_id,principal_id) REFERENCES
            execbound.principals,
        CHECK(credential_id ~ '^[0-9a-f]+$' AND length(credential_id) BETWEEN 2 AND 2048),
        CHECK(public_key ~ '^[0-9a-f]+$' AND length(public_key) BETWEEN 2 AND 8192)
      );
      CREATE INDEX account_passkeys_principal ON execbound.account_passkeys
        (tenant_id,principal_id);
      CREATE TABLE execbound.passkey_challenges(
        tenant_id uuid NOT NULL,session_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN
            ('register','authenticate')),
        challenge text NOT NULL CHECK(challenge ~ '^[0-9a-f]{64}$'),expires_at timestamptz
            NOT NULL,used_at timestamptz,
        PRIMARY KEY(tenant_id,session_id),FOREIGN KEY(tenant_id,session_id) REFERENCES
            execbound.human_sessions
      );
    """)
    for table in ("account_passkeys", "passkey_challenges"):
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON execbound.{table}
            USING(tenant_id=nullif((SELECT current_setting('execbound.tenant_id',true)),'')::uuid)
            WITH CHECK(tenant_id=nullif(
                (SELECT current_setting('execbound.tenant_id',true)),'')::uuid)""")
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC,execbound_app")
        op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")
    change = previous().replace(
        "    ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;",
        PASSKEYS + "    ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;",
    )
    change = change.replace(
        "p_operation IN ('enable','verify')", "p_operation IN ('enable','verify','passkey_verify')"
    )
    change = change.replace(
        "DELETE FROM execbound.session_assurance WHERE",
        (
            "DELETE FROM execbound.account_passkeys WHERE tenant_id=t AND "
            "principal_id=s.principal_id;\n        DELETE FROM "
            "execbound.session_assurance WHERE"
        ),
    )
    op.execute(change)


def downgrade() -> None:
    op.execute(previous())
    op.execute("DROP TABLE execbound.passkey_challenges,execbound.account_passkeys")
