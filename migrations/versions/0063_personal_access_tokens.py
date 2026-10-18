"""Personal access tokens: an administrator's own bearer token for the console API.

A token is a row here and a backing credential in `credentials`, minted in the same function
with a discarded secret, as a sign-in credential is (`sign_in_credential`, 0040). The identity a
token acts as is therefore an ordinary credential-backed ADMIN identity, and every check the
console makes of a session's identity (`policy.store._identity`) applies to it unchanged:
the credential is live, the principal is active with an effective kind of ADMIN, the tenant is
active. Revoking or deleting a token does the same to its credential.
"""

from alembic import op
from sqlalchemy import text

revision = "0063_personal_access_tokens"
down_revision = "0062_people_numbers"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
NEVER = "timestamptz '9999-12-31 00:00:00+00'"
DIGEST = "^[0-9a-f]{64}$"

TABLE = """
CREATE TABLE execbound.personal_access_tokens (
    tenant_id uuid NOT NULL,
    token_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 80),
    token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    revoked_at timestamptz,
    revoked_by uuid,
    last_used_at timestamptz,
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, token_id),
    UNIQUE (token_hash),
    UNIQUE (tenant_id, credential_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals(tenant_id, principal_id),
    FOREIGN KEY (tenant_id, credential_id)
        REFERENCES execbound.credentials(tenant_id, credential_id),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    -- Only a spent token is deleted, and a token is spent when its backing credential is
    -- revoked, which a CHECK on this table cannot see; admin_delete_personal_token decides.
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
)
"""

ACTOR = """
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor AND p.active
           AND p.kind <> 'AGENT' AND execbound.access_effective_kind(p_actor) = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

ISSUE = f"""
CREATE FUNCTION execbound.admin_issue_personal_token(
    p_actor uuid, p_token uuid, p_credential uuid, p_name text, p_token_hash text,
    p_credential_hash text, p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
{ACTOR}
    IF p_issued_at IS NULL OR abs(extract(epoch FROM (p_issued_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_expires_at IS NULL
       OR p_expires_at - p_issued_at < interval '1 hour'
       OR (p_expires_at - p_issued_at > interval '90 days' AND p_expires_at <> {NEVER}) THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    IF p_name IS NULL OR length(btrim(p_name)) NOT BETWEEN 1 AND 80 THEN
        RAISE EXCEPTION 'INVALID_NAME';
    END IF;
    IF p_token IS NULL OR p_credential IS NULL
       OR p_token_hash IS NULL OR p_token_hash !~ '{DIGEST}'
       OR p_credential_hash IS NULL OR p_credential_hash !~ '{DIGEST}' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    -- This lock serializes concurrent issuers for the same owner, but the count it guards
    -- only sees a concurrent committed insert under READ COMMITTED: a caller inside a
    -- snapshot (REPEATABLE READ) transaction would still read its own transaction-start
    -- snapshot here and could let an eleventh token through. Never call this function from a
    -- snapshot transaction.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('execbound.personal_token:' || v_tenant::text || ':' || p_actor::text, 0));
    -- Deactivation (0036), a password reset (0040) and a promotion (0047) revoke every
    -- credential a principal holds without touching this table, so a token row can stay
    -- `live` here while its backing credential is dead. The count joins credentials and
    -- counts only a token whose credential is still unrevoked.
    IF (SELECT count(*) FROM execbound.personal_access_tokens k
         JOIN execbound.credentials c
           ON c.tenant_id = k.tenant_id AND c.credential_id = k.credential_id
         WHERE k.tenant_id = v_tenant AND k.principal_id = p_actor AND k.revoked_at IS NULL
           AND k.deleted_at IS NULL AND k.expires_at > p_issued_at
           AND c.revoked_at IS NULL) >= 10 THEN
        RAISE EXCEPTION 'TOO_MANY_TOKENS';
    END IF;
    INSERT INTO execbound.credentials
        (tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at)
    VALUES (v_tenant, p_credential, p_actor, p_credential_hash, p_issued_at, p_expires_at);
    INSERT INTO execbound.personal_access_tokens
        (tenant_id, token_id, principal_id, credential_id, name, token_hash, created_at, expires_at)
    VALUES (v_tenant, p_token, p_actor, p_credential, btrim(p_name), p_token_hash,
            p_issued_at, p_expires_at);
END $$
"""

REVOKE = f"""
CREATE FUNCTION execbound.admin_revoke_personal_token(
    p_actor uuid, p_token uuid, p_revoked_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_credential uuid;
BEGIN
{ACTOR}
    IF p_revoked_at IS NULL OR abs(extract(epoch FROM (p_revoked_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    UPDATE execbound.personal_access_tokens
       SET revoked_at = p_revoked_at, revoked_by = p_actor
     WHERE tenant_id = v_tenant AND token_id = p_token
       AND revoked_at IS NULL AND deleted_at IS NULL
    RETURNING credential_id INTO v_credential;
    IF v_credential IS NULL THEN
        RAISE EXCEPTION 'INVALID_TOKEN';
    END IF;
    UPDATE execbound.credentials SET revoked_at = p_revoked_at
     WHERE tenant_id = v_tenant AND credential_id = v_credential AND revoked_at IS NULL;
END $$
"""

DELETE = f"""
CREATE FUNCTION execbound.admin_delete_personal_token(
    p_actor uuid, p_token uuid, p_deleted_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_credential uuid;
BEGIN
{ACTOR}
    IF p_deleted_at IS NULL OR abs(extract(epoch FROM (p_deleted_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- A spent token only: revoked itself, revoked through its backing credential, or past
    -- its expiry. Deactivation (0036), a password reset (0040) and a promotion (0047) revoke
    -- the credential without touching this table, and `list_tokens` reports such a token as
    -- revoked, so it is deletable here too. The row's own `revoked_at` stays empty: nobody
    -- revoked the token itself, and the credential keeps when it was revoked.
    UPDATE execbound.personal_access_tokens AS k
       SET deleted_at = p_deleted_at
      FROM execbound.credentials AS c
     WHERE k.tenant_id = v_tenant AND k.token_id = p_token AND k.deleted_at IS NULL
       AND c.tenant_id = k.tenant_id AND c.credential_id = k.credential_id
       AND (k.revoked_at IS NOT NULL OR c.revoked_at IS NOT NULL
            OR k.expires_at <= p_deleted_at)
    RETURNING k.credential_id INTO v_credential;
    IF v_credential IS NULL THEN
        RAISE EXCEPTION 'INVALID_TOKEN';
    END IF;
    UPDATE execbound.credentials SET deleted_at = p_deleted_at
     WHERE tenant_id = v_tenant AND credential_id = v_credential AND deleted_at IS NULL;
END $$
"""

USED = """
CREATE FUNCTION execbound.personal_token_used(p_token uuid, p_used_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_used_at IS NULL OR abs(extract(epoch FROM (p_used_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- Same as the issuing count: a token whose backing credential was revoked out from
    -- under it (deactivation, password reset, promotion) must not look live here either.
    UPDATE execbound.personal_access_tokens AS k SET last_used_at = p_used_at
      FROM execbound.credentials AS c
     WHERE k.tenant_id = v_tenant AND k.token_id = p_token
       AND c.tenant_id = k.tenant_id AND c.credential_id = k.credential_id
       AND c.revoked_at IS NULL
       AND k.revoked_at IS NULL AND k.deleted_at IS NULL AND k.expires_at > p_used_at
       AND (k.last_used_at IS NULL OR k.last_used_at <= p_used_at - interval '1 minute');
END $$
"""

SIGNATURES = (
    "admin_issue_personal_token(uuid, uuid, uuid, text, text, text, timestamptz, timestamptz)",
    "admin_revoke_personal_token(uuid, uuid, timestamptz)",
    "admin_delete_personal_token(uuid, uuid, timestamptz)",
    "personal_token_used(uuid, timestamptz)",
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(TABLE)
    # The FK on (tenant_id, principal_id) needs its own covering index: the primary key is
    # (tenant_id, token_id) and the other FK, on (tenant_id, credential_id), is already
    # covered by the UNIQUE constraint above. The same index backs the live-token count
    # `admin_issue_personal_token` takes its advisory lock over.
    op.execute(
        "CREATE INDEX personal_access_tokens_principal "
        "ON execbound.personal_access_tokens (tenant_id, principal_id)"
    )
    op.execute("ALTER TABLE execbound.personal_access_tokens ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.personal_access_tokens FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON execbound.personal_access_tokens "
        f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
    )
    op.execute("REVOKE ALL ON execbound.personal_access_tokens FROM PUBLIC, execbound_app")
    for role in ("anon", "authenticated", "service_role"):
        if role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.personal_access_tokens FROM {role}")
    op.execute("GRANT SELECT ON execbound.personal_access_tokens TO execbound_app")
    for body in (ISSUE, REVOKE, DELETE, USED):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")
    # Widen the authentication-failure surface catalog (0010) to admit a bearer token:
    # `token` sits alongside `http`, `mcp`, `human` and `monitor`.
    op.execute(
        "ALTER TABLE execbound.authentication_failures "
        "DROP CONSTRAINT authentication_failures_surface_check"
    )
    op.execute(
        "ALTER TABLE execbound.authentication_failures ADD CONSTRAINT "
        "authentication_failures_surface_check "
        "CHECK (surface IN ('http', 'mcp', 'human', 'monitor', 'token'))"
    )


def downgrade() -> None:
    # Deleting history to force a downgrade is not a recovery procedure (this file's own
    # design doc, DATA_MODEL.md). 0010's own downgrade refuses while any authentication
    # failure is retained; this one refuses the same way while any token row or any
    # `token`-surface counter is retained. An owner that does not bypass row security sees no
    # tenant's rows unfenced, so FORCE is lifted around each count and put back before
    # anything else happens, the same shape 0010's downgrade and 0061_replaced_principals's
    # both use.
    op.execute("ALTER TABLE execbound.personal_access_tokens NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.authentication_failures NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    tokens_retained = (
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM execbound.personal_access_tokens)"))
        .scalar_one()
    )
    failures_retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.authentication_failures "
                "WHERE surface = 'token')"
            )
        )
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.personal_access_tokens FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.authentication_failures FORCE ROW LEVEL SECURITY")
    if tokens_retained or failures_retained:
        raise RuntimeError(
            "Personal access tokens require a verified full restore; lossy downgrade refused"
        )
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP TABLE execbound.personal_access_tokens")
    op.execute(
        "ALTER TABLE execbound.authentication_failures "
        "DROP CONSTRAINT authentication_failures_surface_check"
    )
    op.execute(
        "ALTER TABLE execbound.authentication_failures ADD CONSTRAINT "
        "authentication_failures_surface_check "
        "CHECK (surface IN ('http', 'mcp', 'human', 'monitor'))"
    )
