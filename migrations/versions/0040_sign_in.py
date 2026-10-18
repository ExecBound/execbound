"""Regular sign-in: a person's email, their password hash, one-time set-password codes and
the provider identities a Google or GitHub account is bound through.

The runtime role gains SELECT on the three new tables and EXECUTE on the seven functions
below, and no table write at all: a password, a code, an email and an identity are written
only inside the database.

The login form takes an address and no tenant, so resolving it has to read outside the fence.
That is done by two extra **single-row** policies rather than by a definer function that reads
everything: a SELECT on `principals` is permitted when `execbound.sign_in_email` equals that
row's own email, and a SELECT on `principal_identities` when `execbound.sign_in_subject`
equals that row's own provider and subject. Whoever sets the marker can therefore read exactly
the one row for the address or the account they already supplied, and nothing else: no
listing, no enumeration, no other tenant's row. Everything after the resolution happens inside
that tenant's fence like every other read.

A sign-in mints an ordinary `credentials` row whose digest is of 32 random bytes that are
discarded, so nothing can ever present it, and `issue_session` then runs unchanged.

Design: docs/superpowers/specs/2026-09-19-console-sign-in-design.md
(#177's direction, with the customer's own provider left to #177 and #241).
"""

from alembic import op
from sqlalchemy import text

revision = "0040_sign_in"
down_revision = "0039_signups"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
DIGEST = "^[0-9a-f]{64}$"
HEX = "^[0-9a-f]+$"
# An address is normalized before it is written, so the column states what "normalized"
# means rather than trusting the caller: lower case, no spaces, one `@` with something on
# each side, and short enough for the longest address RFC 5321 admits.
EMAIL = "^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$"
PROVIDERS = "('google', 'github')"
METHODS = "('password', 'google', 'github')"

SIGNATURES = (
    "sign_in_credential(uuid, uuid, text, text, timestamptz, timestamptz)",
    "identity_sign_in(uuid, text, text, text, text, timestamptz)",
    "admin_set_email(uuid, uuid, text)",
    "admin_reset_password(uuid, uuid, uuid, text, timestamptz)",
    "password_reset_check(uuid, text)",
    "password_redeem(uuid, text, text, integer, integer, integer, integer, text, text, "
    "timestamptz)",
    "password_replace(uuid, text, integer, integer, integer, integer, text, text, timestamptz)",
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

# A person the console may give a sign-in address or a code to: a principal of this tenant
# that is not an administrator. Administrators are the owner connection's, exactly as
# migration 0036 leaves deactivation to it, so "the console cannot create or change
# administrators" still holds with a password in the world.
TARGET_CHECK = """
    IF p_principal IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
          AND p.kind = 'HUMAN_APPROVER'
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
"""

# What a stored hash must look like wherever one is written. The parameters live beside the
# hash rather than in the server, so raising them is a write and an old row keeps verifying.
HASH_CHECK = f"""
    IF p_algorithm IS NULL OR p_algorithm <> 'scrypt'
       OR p_n IS NULL OR p_n < 16384 OR p_n > 1048576 OR (p_n & (p_n - 1)) <> 0
       OR p_r IS NULL OR p_r < 1 OR p_r > 32
       OR p_p IS NULL OR p_p < 1 OR p_p > 16
       OR p_dklen IS NULL OR p_dklen < 32 OR p_dklen > 64
       OR p_salt IS NULL OR p_salt !~ '{HEX}' OR char_length(p_salt) <> 32
       OR p_hash IS NULL OR p_hash !~ '{HEX}' OR char_length(p_hash) <> p_dklen * 2 THEN
        RAISE EXCEPTION 'INVALID_PASSWORD';
    END IF;
"""

# The credential a verified sign-in mints. Its digest is of bytes the caller discarded, so
# nothing can present it; what it is for is to give `issue_session` the row every session is
# already bound to, so revocation, capacity, renewal and the recheck cover a password and a
# provider session with no new session code.
CREDENTIAL = f"""
CREATE FUNCTION execbound.sign_in_credential(
    p_principal uuid, p_credential uuid, p_token_hash text, p_method text,
    p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_method IS NULL OR p_method NOT IN {METHODS} THEN
        RAISE EXCEPTION 'INVALID_METHOD';
    END IF;
    SELECT p.kind INTO v_kind FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.active
       AND p.kind IN ('HUMAN_APPROVER', 'ADMIN');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF p_credential IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '{DIGEST}' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_issued_at IS NULL OR abs(extract(epoch FROM (p_issued_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_expires_at IS NULL
       OR p_expires_at - p_issued_at < interval '1 minute'
       OR p_expires_at - p_issued_at > interval '8 hours' THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    INSERT INTO execbound.credentials
        (tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at)
    VALUES (v_tenant, p_credential, p_principal, p_token_hash, p_issued_at, p_expires_at);
    RETURN v_kind;
END $$
"""

# A provider account bound to a person. The first sign-in binds the subject to the person the
# verified address named; every later one is identified by the subject alone, and a subject
# already bound to somebody else is refused rather than moved.
IDENTITY = f"""
CREATE FUNCTION execbound.identity_sign_in(
    p_principal uuid, p_provider text, p_subject text, p_email text, p_display_name text,
    p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_bound uuid;
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_provider IS NULL OR p_provider NOT IN {PROVIDERS}
       OR p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'INVALID_IDENTITY';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.active
          AND p.kind IN ('HUMAN_APPROVER', 'ADMIN')
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    SELECT i.principal_id INTO v_bound FROM execbound.principal_identities i
     WHERE i.tenant_id = v_tenant AND i.provider = p_provider AND i.subject = p_subject
       AND i.revoked_at IS NULL FOR UPDATE;
    IF FOUND AND v_bound <> p_principal THEN
        RAISE EXCEPTION 'INVALID_IDENTITY';
    END IF;
    IF NOT FOUND THEN
        INSERT INTO execbound.principal_identities
            (tenant_id, principal_id, provider, subject, email, display_name, created_at,
             last_sign_in_at)
        VALUES (v_tenant, p_principal, p_provider, p_subject, p_email,
                left(btrim(coalesce(p_display_name, '')), 80), p_now, p_now);
        RETURN p_principal;
    END IF;
    UPDATE execbound.principal_identities
       SET last_sign_in_at = p_now, email = p_email,
           display_name = left(btrim(coalesce(p_display_name, '')), 80)
     WHERE tenant_id = v_tenant AND principal_id = p_principal AND provider = p_provider
       AND subject = p_subject AND revoked_at IS NULL;
    RETURN p_principal;
END $$
"""

SET_EMAIL = f"""
CREATE FUNCTION execbound.admin_set_email(p_actor uuid, p_principal uuid, p_email text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_email text := lower(btrim(coalesce(p_email, '')));
BEGIN
    {ACTOR_CHECK}
    {TARGET_CHECK}
    IF v_email !~ '{EMAIL}' OR char_length(v_email) > 254 THEN
        RAISE EXCEPTION 'INVALID_EMAIL';
    END IF;
    BEGIN
        UPDATE execbound.principals SET email = v_email
         WHERE tenant_id = v_tenant AND principal_id = p_principal;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'EMAIL_TAKEN';
    END;
    RETURN v_email;
END $$
"""

# One live code per person: minting revokes whatever was pending, so a code handed over twice
# by mistake leaves exactly one that works.
RESET = f"""
CREATE FUNCTION execbound.admin_reset_password(
    p_actor uuid, p_principal uuid, p_reset uuid, p_token_hash text, p_expires_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_now timestamptz := now();
BEGIN
    {ACTOR_CHECK}
    {TARGET_CHECK}
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
          AND p.active AND p.email IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'INVALID_EMAIL';
    END IF;
    IF p_reset IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '{DIGEST}' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_expires_at IS NULL
       OR p_expires_at - v_now < interval '1 hour'
       OR p_expires_at - v_now > interval '14 days' THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    UPDATE execbound.password_resets SET revoked_at = v_now
     WHERE tenant_id = v_tenant AND principal_id = p_principal
       AND redeemed_at IS NULL AND revoked_at IS NULL;
    INSERT INTO execbound.password_resets
        (tenant_id, reset_id, principal_id, token_hash, created_by, created_at, expires_at)
    VALUES (v_tenant, p_reset, p_principal, p_token_hash, p_actor, v_now, p_expires_at);
END $$
"""

# A secret mismatch is the one refusal that must leave a mark, and a RAISE would roll that
# mark back with everything else, so this counts it, revokes on the fifth and answers NULL.
# Every other refusal raises its code and writes nothing. `onboarding_claim` does the same.
CHECK_CODE = f"""
CREATE FUNCTION execbound.password_reset_check(p_reset uuid, p_token_hash text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_reset execbound.password_resets%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_reset IS NULL THEN
        RAISE EXCEPTION 'INVALID_RESET';
    END IF;
    SELECT * INTO v_reset FROM execbound.password_resets r
     WHERE r.tenant_id = v_tenant AND r.reset_id = p_reset FOR UPDATE;
    IF NOT FOUND OR v_reset.revoked_at IS NOT NULL OR v_reset.redeemed_at IS NOT NULL
       OR v_reset.expires_at <= now() THEN
        RAISE EXCEPTION 'INVALID_RESET';
    END IF;
    IF p_token_hash IS NULL OR p_token_hash !~ '{DIGEST}'
       OR v_reset.token_hash <> p_token_hash THEN
        UPDATE execbound.password_resets
           SET failure_count = failure_count + 1,
               revoked_at = CASE WHEN failure_count + 1 >= 5 THEN now() ELSE revoked_at END
         WHERE tenant_id = v_tenant AND reset_id = p_reset;
        RETURN NULL;
    END IF;
    RETURN v_reset.principal_id;
END $$
"""

# Every instant this writes is the database's own `now()`, because the CHECK constraints beside
# these columns are expressed in it; `p_now` is the caller's clock and is read only to refuse a
# server whose clock disagrees with the database's, exactly as `onboarding_claim` reads it.
#
# Redeeming is also a recovery, so it ends every session and credential the person had: a code
# somebody else could have read must not leave the previous holder signed in. The identifiers
# come back so the caller appends one audit event per row in the same transaction, which is
# what `admin_deactivate_principal` already does.
REDEEM = f"""
CREATE FUNCTION execbound.password_redeem(
    p_reset uuid, p_token_hash text, p_algorithm text, p_n integer, p_r integer, p_p integer,
    p_dklen integer, p_salt text, p_hash text, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid;
    v_now timestamptz := now();
    v_credentials jsonb;
    v_sessions jsonb;
BEGIN
    v_principal := execbound.password_reset_check(p_reset, p_token_hash);
    IF v_principal IS NULL THEN
        RETURN NULL;
    END IF;
    {HASH_CHECK}
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = v_principal AND p.active
          AND p.kind IN ('HUMAN_APPROVER', 'ADMIN')
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    INSERT INTO execbound.principal_passwords
        (tenant_id, principal_id, algorithm, n, r, p, dklen, salt, hash, created_at, updated_at)
    VALUES (v_tenant, v_principal, p_algorithm, p_n, p_r, p_p, p_dklen, p_salt, p_hash,
            v_now, v_now)
    ON CONFLICT (tenant_id, principal_id) DO UPDATE
        SET algorithm = excluded.algorithm, n = excluded.n, r = excluded.r, p = excluded.p,
            dklen = excluded.dklen, salt = excluded.salt, hash = excluded.hash,
            updated_at = excluded.updated_at;
    UPDATE execbound.password_resets SET redeemed_at = v_now
     WHERE tenant_id = v_tenant AND reset_id = p_reset;
    WITH revoked AS (
        UPDATE execbound.credentials SET revoked_at = v_now
        WHERE tenant_id = v_tenant AND principal_id = v_principal AND revoked_at IS NULL
        RETURNING credential_id
    )
    SELECT COALESCE(jsonb_agg(credential_id), '[]'::jsonb) INTO v_credentials FROM revoked;
    WITH ended AS (
        UPDATE execbound.human_sessions SET revoked_at = v_now
        WHERE tenant_id = v_tenant AND principal_id = v_principal AND revoked_at IS NULL
        RETURNING session_id
    )
    SELECT COALESCE(jsonb_agg(session_id), '[]'::jsonb) INTO v_sessions FROM ended;
    RETURN jsonb_build_object('principal_id', v_principal, 'credentials', v_credentials,
                              'sessions', v_sessions);
END $$
"""

# A change, never a set: the row must already exist, so nothing that skips the current-password
# check can create a password through this door.
REPLACE = f"""
CREATE FUNCTION execbound.password_replace(
    p_principal uuid, p_algorithm text, p_n integer, p_r integer, p_p integer, p_dklen integer,
    p_salt text, p_hash text, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.active
          AND p.kind IN ('HUMAN_APPROVER', 'ADMIN')
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    {HASH_CHECK}
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    UPDATE execbound.principal_passwords
       SET algorithm = p_algorithm, n = p_n, r = p_r, p = p_p, dklen = p_dklen,
           salt = p_salt, hash = p_hash, updated_at = now()
     WHERE tenant_id = v_tenant AND principal_id = p_principal;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
END $$
"""

FUNCTIONS = (CREDENTIAL, IDENTITY, SET_EMAIL, RESET, CHECK_CODE, REDEEM, REPLACE)

# The two single-row reads the sign-in needs before it knows a tenant. Each permits exactly
# the row whose own key equals the marker the caller supplied, so setting the marker reveals
# whether the address or the account the caller already typed belongs to somebody, and never
# which other rows exist. Both are permissive SELECT policies beside the tenant isolation
# policy, which keeps deciding every write and every other read.
EMAIL_POLICY = """
CREATE POLICY sign_in_email ON execbound.principals FOR SELECT
USING (email IS NOT NULL
       AND email = nullif((SELECT current_setting('execbound.sign_in_email', true)), ''))
"""
SUBJECT_POLICY = """
CREATE POLICY sign_in_subject ON execbound.principal_identities FOR SELECT
USING (revoked_at IS NULL
       AND provider || ':' || subject
           = nullif((SELECT current_setting('execbound.sign_in_subject', true)), ''))
"""


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _protect(table: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.{table}
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role", "execbound_app"):
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")


def upgrade() -> None:
    # The address a person signs in with. Unique across every tenant, because the form takes
    # an address and no tenant: one sign-in address belongs to one person in one tenant. A
    # tenant selector on the form would tell a stranger which tenants exist.
    op.execute(
        "ALTER TABLE execbound.principals ADD COLUMN email text "
        f"CHECK (email IS NULL OR (email ~ '{EMAIL}' AND char_length(email) <= 254 "
        "AND email = lower(email)))"
    )
    op.execute(
        "CREATE UNIQUE INDEX principals_email ON execbound.principals (email) "
        "WHERE email IS NOT NULL"
    )
    op.execute(EMAIL_POLICY)
    op.execute(f"""
        CREATE TABLE execbound.principal_passwords (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            principal_id uuid NOT NULL,
            algorithm text NOT NULL CHECK (algorithm = 'scrypt'),
            n integer NOT NULL CHECK (n BETWEEN 16384 AND 1048576),
            r integer NOT NULL CHECK (r BETWEEN 1 AND 32),
            p integer NOT NULL CHECK (p BETWEEN 1 AND 16),
            dklen integer NOT NULL CHECK (dklen BETWEEN 32 AND 64),
            salt text NOT NULL CHECK (salt ~ '{HEX}' AND char_length(salt) = 32),
            hash text NOT NULL CHECK (hash ~ '{HEX}' AND char_length(hash) = dklen * 2),
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
            PRIMARY KEY (tenant_id, principal_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id)
        )
    """)
    _protect("principal_passwords")
    op.execute(f"""
        CREATE TABLE execbound.password_resets (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            reset_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            token_hash text NOT NULL CHECK (token_hash ~ '{DIGEST}'),
            created_by uuid NOT NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
            redeemed_at timestamptz CHECK (redeemed_at IS NULL OR redeemed_at >= created_at),
            revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count BETWEEN 0 AND 5),
            PRIMARY KEY (tenant_id, reset_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id)
        )
    """)
    _protect("password_resets")
    # At most one live code per person; minting revokes the pending one first.
    op.execute(
        "CREATE UNIQUE INDEX password_resets_live ON execbound.password_resets "
        "(tenant_id, principal_id) WHERE redeemed_at IS NULL AND revoked_at IS NULL"
    )
    # The partial index above cannot cover the foreign key, so the person's codes get a
    # plain one: a deactivation reads them by person, and every foreign key here is indexed.
    op.execute(
        "CREATE INDEX password_resets_person ON execbound.password_resets (tenant_id, principal_id)"
    )
    op.execute(f"""
        CREATE TABLE execbound.principal_identities (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            principal_id uuid NOT NULL,
            provider text NOT NULL CHECK (provider IN {PROVIDERS}),
            subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
            email text CHECK (email IS NULL OR char_length(email) <= 254),
            display_name text CHECK (display_name IS NULL OR char_length(display_name) <= 80),
            created_at timestamptz NOT NULL,
            last_sign_in_at timestamptz,
            revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            PRIMARY KEY (tenant_id, principal_id, provider, subject),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id)
        )
    """)
    _protect("principal_identities")
    op.execute(SUBJECT_POLICY)
    # One provider account is at most one person anywhere, which is why this index is not
    # scoped to a tenant; and one person holds at most one account per provider.
    op.execute(
        "CREATE UNIQUE INDEX principal_identities_subject ON execbound.principal_identities "
        "(provider, subject) WHERE revoked_at IS NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX principal_identities_person ON execbound.principal_identities "
        "(tenant_id, principal_id, provider) WHERE revoked_at IS NULL"
    )
    # A wrong password against a known person is counted against that person, so the People
    # page can show it beside the credential failures it already shows.
    op.execute(
        "ALTER TABLE execbound.authentication_failures DROP CONSTRAINT "
        "authentication_failures_subject_kind_check"
    )
    op.execute(
        "ALTER TABLE execbound.authentication_failures ADD CONSTRAINT "
        "authentication_failures_subject_kind_check "
        "CHECK (subject_kind IN ('credential', 'source', 'principal'))"
    )
    for body in FUNCTIONS:
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if _role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    # Nothing here is history: a password, a code and a provider link are current state, and a
    # deployment that goes back to credential sign-in keeps every audit event about them. A
    # failure row attributed to a person is the one thing that would be lost, so it is refused
    # rather than deleted.
    retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM execbound.authentication_failures "
                "WHERE subject_kind = 'principal'"
            )
        )
        .scalar_one()
    )
    if retained:
        raise RuntimeError(
            "Cannot downgrade while authentication failures are attributed to a person"
        )
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute(
        "ALTER TABLE execbound.authentication_failures DROP CONSTRAINT "
        "authentication_failures_subject_kind_check"
    )
    op.execute(
        "ALTER TABLE execbound.authentication_failures ADD CONSTRAINT "
        "authentication_failures_subject_kind_check "
        "CHECK (subject_kind IN ('credential', 'source'))"
    )
    op.execute("DROP TABLE execbound.principal_identities")
    op.execute("DROP TABLE execbound.password_resets")
    op.execute("DROP TABLE execbound.principal_passwords")
    op.execute("DROP POLICY sign_in_email ON execbound.principals")
    op.execute("DROP INDEX execbound.principals_email")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN email")
