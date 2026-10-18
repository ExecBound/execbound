"""The customer's own identity provider: the provider a tenant registers, the links between a
person and a directory account, the one-time invitation codes that bind them, and the directory
sign-ins the recheck redeems a refresh token for.

Migration 0040 gave a person a password and, beside it, the Google or GitHub account the
deployment configured. This is the other half: a provider that belongs to a tenant rather than
to the deployment, registered by that tenant's administrator. It is a separate family of tables
rather than columns on 0040's, and the reason is uniqueness: a Google subject identifies one
account in the world, and a directory subject identifies one account **in that directory**, so
the index that holds a link unique is per provider row and cannot be the global one 0040 wrote.
The custody is different too, because only this half holds a client secret and a refresh token.

The runtime role gains SELECT on the four tables and EXECUTE on the eleven functions below, and
no table write at all. A provider, a link, an invitation and a sign-in are written only inside
the database.

The client secret and the refresh token are stored as AES-256-GCM ciphertext under a key ring
the deployment holds in its private configuration, with the key id beside the ciphertext and the
tenant, the provider and the purpose as additional authenticated data, so a row cannot be moved
to another tenant, another provider or another purpose and still open. The key is never here:
what a reader of this database gets is ciphertext.

`identity_links` carries one extra single-row SELECT policy, exactly as 0040's two: a row is
readable when `execbound.directory_subject` equals that row's own provider and subject. The
callback holds a verified assertion for one account and needs to know which tenant it belongs to
before it can enter a fence; setting the marker answers about that one account and about no
other row in any tenant.

Design: docs/superpowers/specs/2026-09-20-customer-identity-provider-design.md (#177, #241).
"""

from alembic import op
from sqlalchemy import text

revision = "0043_directory_sign_in"
down_revision = "0042_console_invitations"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
DIGEST = "^[0-9a-f]{64}$"
HEX = "^[0-9a-f]+$"
KEY_ID = "^[A-Za-z0-9_.-]{1,64}$"
HTTPS = "^https://[^[:space:]]+$"
STATES = "('draft', 'verified', 'enabled', 'disabled')"
REQUESTABLE = "('enabled', 'disabled')"
VIA = "('invitation', 'self', 'admin')"
CLAIMS = "('sub', 'oid')"
REASONS = "('PROVIDER_REFUSED', 'LINK_REVOKED', 'PROVIDER_DISABLED')"
MAX_FAILURES = 5

SIGNATURES = (
    "directory_register(uuid, uuid, text, text, text, text, text, text, text, text, text, "
    "text, timestamptz)",
    "directory_set_state(uuid, uuid, text, timestamptz)",
    "directory_link_self(uuid, uuid, text, text, text, timestamptz)",
    "directory_link(uuid, uuid, uuid, text, timestamptz)",
    "directory_unlink(uuid, uuid, timestamptz)",
    "directory_invite(uuid, uuid, uuid, uuid, text, timestamptz)",
    "directory_invitation_revoke(uuid, uuid, timestamptz)",
    "directory_invitation_check(uuid, text)",
    "directory_sign_in(uuid, text, uuid, uuid, text, text, text, text, text, timestamptz, "
    "timestamptz)",
    "directory_recheck(uuid, text, text, timestamptz)",
    "directory_revoke(uuid, text, timestamptz)",
)

# Migration 0021's preamble, restated: the tenant comes from the fence setting, and the actor
# must be an active ADMIN of that active tenant.
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

# A person the console may link or invite: a principal of this tenant that is not an
# administrator. Administrators link themselves and are otherwise the owner connection's, so
# "the console cannot create or change administrators" still holds with a directory in the
# world. The same rule `admin_set_email` applies to an address applies here to a directory
# account, and for the same reason: an administrator is not something the console hands out.
TARGET_CHECK = """
    IF p_principal IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
          AND p.kind = 'HUMAN_APPROVER'
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
"""

# Every directory credential under one provider, with the sessions standing on it. Disabling a
# provider and unlinking a person both end access, and both do it here rather than leaving the
# caller to walk the rows outside the transaction that decided.
REVOKE_UNDER = """
    WITH ended AS (
        UPDATE execbound.federated_sign_ins f SET revoked_reason = {reason}
         WHERE f.tenant_id = v_tenant AND f.revoked_reason IS NULL
           AND {predicate}
        RETURNING f.credential_id
    ), credentials AS (
        UPDATE execbound.credentials c SET revoked_at = v_now
         WHERE c.tenant_id = v_tenant AND c.credential_id IN (SELECT credential_id FROM ended)
           AND c.revoked_at IS NULL
        RETURNING c.credential_id
    ), sessions AS (
        UPDATE execbound.human_sessions s SET revoked_at = v_now
         WHERE s.tenant_id = v_tenant AND s.credential_id IN (SELECT credential_id FROM ended)
           AND s.revoked_at IS NULL
        RETURNING s.session_id
    )
    SELECT jsonb_build_object(
        'credentials', COALESCE((SELECT jsonb_agg(credential_id) FROM credentials), '[]'::jsonb),
        'sessions', COALESCE((SELECT jsonb_agg(session_id) FROM sessions), '[]'::jsonb))
      INTO v_ended;
"""

REGISTER = f"""
CREATE FUNCTION execbound.directory_register(
    p_actor uuid, p_provider uuid, p_name text, p_issuer text, p_client_id text,
    p_secret_ciphertext text, p_secret_key_id text, p_subject_claim text, p_issuer_tenant text,
    p_authorization_endpoint text, p_token_endpoint text, p_jwks_uri text, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    IF p_provider IS NULL OR p_subject_claim IS NULL OR p_subject_claim NOT IN {CLAIMS} THEN
        RAISE EXCEPTION 'INVALID_PROVIDER';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    BEGIN
        INSERT INTO execbound.identity_providers
            (tenant_id, provider_id, name, issuer, client_id, client_auth, secret_ciphertext,
             secret_key_id, subject_claim, issuer_tenant, authorization_endpoint, token_endpoint,
             jwks_uri, discovery_fetched_at, state, created_by, created_at)
        VALUES (v_tenant, p_provider, left(btrim(coalesce(p_name, '')), 80), p_issuer,
                p_client_id, 'client_secret_post', p_secret_ciphertext, p_secret_key_id,
                p_subject_claim, p_issuer_tenant, p_authorization_endpoint, p_token_endpoint,
                p_jwks_uri, now(), 'draft', p_actor, now());
    EXCEPTION
        WHEN unique_violation THEN RAISE EXCEPTION 'PROVIDER_EXISTS';
        WHEN check_violation THEN RAISE EXCEPTION 'INVALID_PROVIDER';
    END;
END $$
"""

SET_STATE = f"""
CREATE FUNCTION execbound.directory_set_state(
    p_actor uuid, p_provider uuid, p_state text, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_now timestamptz := now();
    v_current text;
    v_ended jsonb := jsonb_build_object('credentials', '[]'::jsonb, 'sessions', '[]'::jsonb);
BEGIN
    {ACTOR_CHECK}
    -- `verified` is never requestable. It is evidence that somebody completed a sign-in, and
    -- the only thing that may write it is the sign-in that did.
    IF p_state IS NULL OR p_state NOT IN {REQUESTABLE} THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    SELECT p.state INTO v_current FROM execbound.identity_providers p
     WHERE p.tenant_id = v_tenant AND p.provider_id = p_provider FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_PROVIDER';
    END IF;
    IF p_state = 'enabled' AND v_current = 'draft' THEN
        -- Enabling a provider nobody has signed in through is how a tenant locks itself out.
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF p_state = v_current THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF p_state = 'disabled' THEN
        {REVOKE_UNDER.format(predicate="f.provider_id = p_provider", reason="'PROVIDER_DISABLED'")}
        UPDATE execbound.identity_providers
           SET state = 'disabled', disabled_at = v_now
         WHERE tenant_id = v_tenant AND provider_id = p_provider;
    ELSE
        BEGIN
            UPDATE execbound.identity_providers
               SET state = 'enabled', enabled_at = v_now, disabled_at = NULL
             WHERE tenant_id = v_tenant AND provider_id = p_provider;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION 'PROVIDER_EXISTS';
        END;
    END IF;
    RETURN v_ended || jsonb_build_object('previous', v_current);
END $$
"""

# Any administrator or approver may link their own account, and nobody else's. Self-linking
# changes nothing about who is an administrator, so it stays inside 0021's invariant; the first
# one through a draft provider is also what proves the registration works, and marks it
# verified.
LINK_SELF = """
CREATE FUNCTION execbound.directory_link_self(
    p_actor uuid, p_provider uuid, p_subject text, p_display_name text, p_display_username text,
    p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_now timestamptz := now();
    v_state text;
    v_kind text;
    v_link uuid := gen_random_uuid();
    v_verified boolean := false;
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    SELECT p.kind INTO v_kind FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
       AND p.active AND p.kind IN ('HUMAN_APPROVER', 'ADMIN');
    IF p_actor IS NULL OR NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'INVALID_SUBJECT';
    END IF;
    SELECT p.state INTO v_state FROM execbound.identity_providers p
     WHERE p.tenant_id = v_tenant AND p.provider_id = p_provider FOR UPDATE;
    IF NOT FOUND OR v_state = 'disabled' THEN
        RAISE EXCEPTION 'INVALID_PROVIDER';
    END IF;
    BEGIN
        INSERT INTO execbound.identity_links
            (tenant_id, link_id, principal_id, provider_id, subject, via, display_name,
             display_username, created_by, created_at)
        VALUES (v_tenant, v_link, p_actor, p_provider, p_subject, 'self',
                left(btrim(coalesce(p_display_name, '')), 80),
                left(btrim(coalesce(p_display_username, '')), 120), p_actor, v_now);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'ALREADY_LINKED';
    END;
    IF v_state = 'draft' THEN
        UPDATE execbound.identity_providers
           SET state = 'verified', verified_by = p_actor, verified_at = v_now
         WHERE tenant_id = v_tenant AND provider_id = p_provider;
        v_verified := true;
    END IF;
    RETURN jsonb_build_object('link_id', v_link, 'verified', v_verified, 'kind', v_kind);
END $$
"""

LINK = f"""
CREATE FUNCTION execbound.directory_link(
    p_actor uuid, p_principal uuid, p_provider uuid, p_subject text, p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_link uuid := gen_random_uuid();
BEGIN
    {ACTOR_CHECK}
    {TARGET_CHECK}
    IF p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'INVALID_SUBJECT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.identity_providers p
        WHERE p.tenant_id = v_tenant AND p.provider_id = p_provider AND p.state <> 'disabled'
    ) THEN
        RAISE EXCEPTION 'INVALID_PROVIDER';
    END IF;
    BEGIN
        INSERT INTO execbound.identity_links
            (tenant_id, link_id, principal_id, provider_id, subject, via, created_by, created_at)
        VALUES (v_tenant, v_link, p_principal, p_provider, p_subject, 'admin', p_actor, now());
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'ALREADY_LINKED';
    END;
    RETURN v_link;
END $$
"""

UNLINK = f"""
CREATE FUNCTION execbound.directory_unlink(p_actor uuid, p_principal uuid, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_now timestamptz := now();
    v_link uuid;
    v_ended jsonb := jsonb_build_object('credentials', '[]'::jsonb, 'sessions', '[]'::jsonb);
BEGIN
    {ACTOR_CHECK}
    {TARGET_CHECK}
    SELECT l.link_id INTO v_link FROM execbound.identity_links l
     WHERE l.tenant_id = v_tenant AND l.principal_id = p_principal AND l.revoked_at IS NULL
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_LINK';
    END IF;
    {REVOKE_UNDER.format(predicate="f.link_id = v_link", reason="'LINK_REVOKED'")}
    UPDATE execbound.identity_links SET revoked_at = v_now
     WHERE tenant_id = v_tenant AND link_id = v_link;
    RETURN v_ended || jsonb_build_object('link_id', v_link);
END $$
"""

INVITE = f"""
CREATE FUNCTION execbound.directory_invite(
    p_actor uuid, p_principal uuid, p_provider uuid, p_invitation uuid, p_token_hash text,
    p_expires_at timestamptz)
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
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.active
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.identity_links l
        WHERE l.tenant_id = v_tenant AND l.principal_id = p_principal AND l.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'ALREADY_LINKED';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.identity_providers p
        WHERE p.tenant_id = v_tenant AND p.provider_id = p_provider AND p.state = 'enabled'
    ) THEN
        RAISE EXCEPTION 'INVALID_PROVIDER';
    END IF;
    IF p_invitation IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '{DIGEST}' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_expires_at IS NULL
       OR p_expires_at - v_now < interval '1 hour'
       OR p_expires_at - v_now > interval '14 days' THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    -- One live code per person: minting revokes whatever was pending, so a code handed over
    -- twice by mistake leaves exactly one that works.
    UPDATE execbound.identity_invitations SET revoked_at = v_now
     WHERE tenant_id = v_tenant AND principal_id = p_principal
       AND redeemed_at IS NULL AND revoked_at IS NULL;
    INSERT INTO execbound.identity_invitations
        (tenant_id, invitation_id, principal_id, provider_id, token_hash, created_by, created_at,
         expires_at)
    VALUES (v_tenant, p_invitation, p_principal, p_provider, p_token_hash, p_actor, v_now,
            p_expires_at);
END $$
"""

INVITATION_REVOKE = f"""
CREATE FUNCTION execbound.directory_invitation_revoke(
    p_actor uuid, p_invitation uuid, p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid;
BEGIN
    {ACTOR_CHECK}
    UPDATE execbound.identity_invitations SET revoked_at = now()
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation
       AND redeemed_at IS NULL AND revoked_at IS NULL
    RETURNING principal_id INTO v_principal;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    RETURN v_principal;
END $$
"""

# A secret mismatch is the one refusal that must leave a mark, and a RAISE would roll that mark
# back with everything else, so this counts it, revokes on the fifth and answers NULL. Every
# other refusal raises its code and writes nothing. `onboarding_claim` and
# `password_reset_check` do the same, and a redeemed, revoked, expired and wrong code all reach
# the caller as the same sentence.
INVITATION_CHECK = f"""
CREATE FUNCTION execbound.directory_invitation_check(p_invitation uuid, p_token_hash text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_row execbound.identity_invitations%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_invitation IS NULL THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    SELECT * INTO v_row FROM execbound.identity_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND OR v_row.revoked_at IS NOT NULL OR v_row.redeemed_at IS NOT NULL
       OR v_row.expires_at <= now() THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    IF p_token_hash IS NULL OR p_token_hash !~ '{DIGEST}'
       OR v_row.token_hash <> p_token_hash THEN
        UPDATE execbound.identity_invitations
           SET failure_count = failure_count + 1,
               revoked_at = CASE WHEN failure_count + 1 >= {MAX_FAILURES} THEN now()
                                 ELSE revoked_at END
         WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.identity_providers p
        WHERE p.tenant_id = v_tenant AND p.provider_id = v_row.provider_id
          AND p.state = 'enabled'
    ) THEN
        RAISE EXCEPTION 'INVALID_PROVIDER';
    END IF;
    RETURN v_row.provider_id;
END $$
"""

# The atomic one. With an invitation, the invitation is locked, the link is inserted, the
# invitation is stamped redeemed with the subject and the credential is minted in one statement
# sequence, so two browsers redeeming the same code at the same moment produce exactly one
# session. Without one, an active link is required: a subject nobody linked is refused and never
# created.
SIGN_IN = f"""
CREATE FUNCTION execbound.directory_sign_in(
    p_provider uuid, p_subject text, p_invitation uuid, p_credential uuid, p_token_hash text,
    p_refresh_ciphertext text, p_refresh_key_id text, p_display_name text,
    p_display_username text, p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_now timestamptz := now();
    v_principal uuid;
    v_link uuid;
    v_kind text;
    v_row execbound.identity_invitations%ROWTYPE;
    v_name text := left(btrim(coalesce(p_display_name, '')), 80);
    v_username text := left(btrim(coalesce(p_display_username, '')), 120);
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'INVALID_SUBJECT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.identity_providers p
        WHERE p.tenant_id = v_tenant AND p.provider_id = p_provider AND p.state = 'enabled'
    ) THEN
        RAISE EXCEPTION 'INVALID_PROVIDER';
    END IF;
    IF p_credential IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '{DIGEST}' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_issued_at IS NULL OR abs(extract(epoch FROM (p_issued_at - v_now))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_expires_at IS NULL
       OR p_expires_at - p_issued_at < interval '1 minute'
       OR p_expires_at - p_issued_at > interval '8 hours' THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    IF p_invitation IS NOT NULL THEN
        SELECT * INTO v_row FROM execbound.identity_invitations i
         WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
        IF NOT FOUND OR v_row.revoked_at IS NOT NULL OR v_row.redeemed_at IS NOT NULL
           OR v_row.expires_at <= v_now OR v_row.provider_id <> p_provider THEN
            RAISE EXCEPTION 'INVALID_INVITATION';
        END IF;
        v_principal := v_row.principal_id;
        v_link := gen_random_uuid();
        BEGIN
            INSERT INTO execbound.identity_links
                (tenant_id, link_id, principal_id, provider_id, subject, via, invitation_id,
                 display_name, display_username, created_by, created_at, last_sign_in_at)
            VALUES (v_tenant, v_link, v_principal, p_provider, p_subject, 'invitation',
                    p_invitation, v_name, v_username, v_row.created_by, v_now, v_now);
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION 'ALREADY_LINKED';
        END;
        UPDATE execbound.identity_invitations
           SET redeemed_at = v_now, redeemed_subject = p_subject
         WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    ELSE
        SELECT l.link_id, l.principal_id INTO v_link, v_principal
          FROM execbound.identity_links l
         WHERE l.tenant_id = v_tenant AND l.provider_id = p_provider AND l.subject = p_subject
           AND l.revoked_at IS NULL FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'INVALID_LINK';
        END IF;
        UPDATE execbound.identity_links
           SET last_sign_in_at = v_now, display_name = v_name, display_username = v_username
         WHERE tenant_id = v_tenant AND link_id = v_link;
    END IF;
    SELECT p.kind INTO v_kind FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.principal_id = v_principal AND p.active
       AND p.kind IN ('HUMAN_APPROVER', 'ADMIN');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    INSERT INTO execbound.credentials
        (tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at)
    VALUES (v_tenant, p_credential, v_principal, p_token_hash, p_issued_at, p_expires_at);
    INSERT INTO execbound.federated_sign_ins
        (tenant_id, credential_id, provider_id, principal_id, link_id, subject,
         refresh_ciphertext, refresh_key_id, created_at, verified_at)
    VALUES (v_tenant, p_credential, p_provider, v_principal, v_link, p_subject,
            p_refresh_ciphertext, p_refresh_key_id, v_now, v_now);
    RETURN jsonb_build_object('principal_id', v_principal, 'link_id', v_link, 'kind', v_kind);
END $$
"""

RECHECK = """
CREATE FUNCTION execbound.directory_recheck(
    p_credential uuid, p_refresh_ciphertext text, p_refresh_key_id text, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET verified_at = now(),
           refresh_ciphertext = coalesce(p_refresh_ciphertext, refresh_ciphertext),
           refresh_key_id = coalesce(p_refresh_key_id, refresh_key_id)
     WHERE tenant_id = v_tenant AND credential_id = p_credential AND revoked_reason IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_CREDENTIAL';
    END IF;
END $$
"""

REVOKE = f"""
CREATE FUNCTION execbound.directory_revoke(
    p_credential uuid, p_reason text, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_now timestamptz := now();
    v_ended jsonb := jsonb_build_object('credentials', '[]'::jsonb, 'sessions', '[]'::jsonb);
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_reason IS NULL OR p_reason NOT IN {REASONS} THEN
        RAISE EXCEPTION 'INVALID_REASON';
    END IF;
    {REVOKE_UNDER.format(predicate="f.credential_id = p_credential", reason="p_reason")}
    RETURN v_ended;
END $$
"""

FUNCTIONS = (
    REGISTER,
    SET_STATE,
    LINK_SELF,
    LINK,
    UNLINK,
    INVITE,
    INVITATION_REVOKE,
    INVITATION_CHECK,
    SIGN_IN,
    RECHECK,
    REVOKE,
)

# The one read the callback needs before it knows a tenant. It permits exactly the row whose own
# provider and subject equal the marker the caller supplied, so setting the marker answers about
# the one account this server already holds a verified assertion for and about no other row in
# any tenant. A permissive SELECT policy beside the tenant isolation policy, which keeps deciding
# every write and every other read.
# The provider a sign-in link names. One redirect URI serves every tenant, so the two public
# halves of a flow hold a provider id and no tenant at all, and the tenant has to come from the
# row itself before any fence can be entered. This permits exactly the row whose own id equals
# the marker, and only while it is not disabled, so the id an administrator distributes as the
# tenant's sign-in address answers about that provider and about no other row in any tenant. A
# disabled provider answers nothing, which is what ends a flow that was already in the air.
PROVIDER_POLICY = """
CREATE POLICY directory_provider ON execbound.identity_providers FOR SELECT
USING (state <> 'disabled'
       AND provider_id::text
           = nullif((SELECT current_setting('execbound.directory_provider', true)), ''))
"""

SUBJECT_POLICY = """
CREATE POLICY directory_subject ON execbound.identity_links FOR SELECT
USING (revoked_at IS NULL
       AND provider_id::text || ':' || subject
           = nullif((SELECT current_setting('execbound.directory_subject', true)), ''))
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
    op.execute(f"""
        CREATE TABLE execbound.identity_providers (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            provider_id uuid NOT NULL,
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
            issuer text NOT NULL CHECK (issuer ~ '{HTTPS}' AND char_length(issuer) <= 512),
            client_id text NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 256),
            client_auth text NOT NULL CHECK (client_auth = 'client_secret_post'),
            secret_ciphertext text NOT NULL
                CHECK (secret_ciphertext ~ '{HEX}'
                       AND char_length(secret_ciphertext) BETWEEN 56 AND 8192),
            secret_key_id text NOT NULL CHECK (secret_key_id ~ '{KEY_ID}'),
            subject_claim text NOT NULL CHECK (subject_claim IN {CLAIMS}),
            issuer_tenant text CHECK (issuer_tenant IS NULL
                                      OR char_length(issuer_tenant) BETWEEN 1 AND 64),
            authorization_endpoint text NOT NULL CHECK (authorization_endpoint ~ '{HTTPS}'),
            token_endpoint text NOT NULL CHECK (token_endpoint ~ '{HTTPS}'),
            jwks_uri text NOT NULL CHECK (jwks_uri ~ '{HTTPS}'),
            discovery_fetched_at timestamptz NOT NULL,
            state text NOT NULL CHECK (state IN {STATES}),
            created_by uuid NOT NULL,
            created_at timestamptz NOT NULL,
            verified_by uuid,
            verified_at timestamptz,
            enabled_at timestamptz,
            disabled_at timestamptz,
            PRIMARY KEY (tenant_id, provider_id),
            FOREIGN KEY (tenant_id, created_by)
                REFERENCES execbound.principals (tenant_id, principal_id),
            CHECK (state <> 'draft' OR verified_at IS NULL),
            CHECK (state NOT IN ('verified', 'enabled') OR verified_at IS NOT NULL)
        )
    """)
    _protect("identity_providers")
    op.execute(PROVIDER_POLICY)
    # One provider per tenant that is not disabled. A second registration is refused here
    # rather than by a read that could race with it.
    op.execute(
        "CREATE UNIQUE INDEX identity_providers_live ON execbound.identity_providers "
        "(tenant_id) WHERE state <> 'disabled'"
    )
    op.execute(
        "CREATE INDEX identity_providers_creator ON execbound.identity_providers "
        "(tenant_id, created_by)"
    )
    op.execute(f"""
        CREATE TABLE execbound.identity_links (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            link_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            provider_id uuid NOT NULL,
            subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
            via text NOT NULL CHECK (via IN {VIA}),
            invitation_id uuid,
            display_name text CHECK (display_name IS NULL OR char_length(display_name) <= 80),
            display_username text
                CHECK (display_username IS NULL OR char_length(display_username) <= 120),
            created_by uuid NOT NULL,
            created_at timestamptz NOT NULL,
            last_sign_in_at timestamptz,
            revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            PRIMARY KEY (tenant_id, link_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id),
            FOREIGN KEY (tenant_id, provider_id)
                REFERENCES execbound.identity_providers (tenant_id, provider_id)
        )
    """)
    _protect("identity_links")
    op.execute(SUBJECT_POLICY)
    # One account in one directory is one person. The index is keyed on the provider row rather
    # than on a provider name, because two customers' directories are two namespaces and a
    # subject that collides across them is not the same account.
    op.execute(
        "CREATE UNIQUE INDEX identity_links_subject ON execbound.identity_links "
        "(provider_id, subject) WHERE revoked_at IS NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX identity_links_person ON execbound.identity_links "
        "(tenant_id, principal_id) WHERE revoked_at IS NULL"
    )
    # The partial indexes above cannot cover the foreign keys, so each gets a plain one.
    op.execute(
        "CREATE INDEX identity_links_person_all ON execbound.identity_links "
        "(tenant_id, principal_id)"
    )
    op.execute(
        "CREATE INDEX identity_links_provider ON execbound.identity_links (tenant_id, provider_id)"
    )
    op.execute(f"""
        CREATE TABLE execbound.identity_invitations (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            invitation_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            provider_id uuid NOT NULL,
            token_hash text NOT NULL CHECK (token_hash ~ '{DIGEST}'),
            created_by uuid NOT NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
            redeemed_at timestamptz CHECK (redeemed_at IS NULL OR redeemed_at >= created_at),
            redeemed_subject text
                CHECK (redeemed_subject IS NULL OR char_length(redeemed_subject) <= 255),
            failure_count integer NOT NULL DEFAULT 0
                CHECK (failure_count BETWEEN 0 AND {MAX_FAILURES}),
            revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            PRIMARY KEY (tenant_id, invitation_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id),
            FOREIGN KEY (tenant_id, provider_id)
                REFERENCES execbound.identity_providers (tenant_id, provider_id),
            CHECK ((redeemed_at IS NULL) = (redeemed_subject IS NULL))
        )
    """)
    _protect("identity_invitations")
    op.execute(
        "CREATE UNIQUE INDEX identity_invitations_live ON execbound.identity_invitations "
        "(tenant_id, principal_id) WHERE redeemed_at IS NULL AND revoked_at IS NULL"
    )
    op.execute(
        "CREATE INDEX identity_invitations_person ON execbound.identity_invitations "
        "(tenant_id, principal_id)"
    )
    op.execute(
        "CREATE INDEX identity_invitations_provider ON execbound.identity_invitations "
        "(tenant_id, provider_id)"
    )
    op.execute(f"""
        CREATE TABLE execbound.federated_sign_ins (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            credential_id uuid NOT NULL,
            provider_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            link_id uuid NOT NULL,
            subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
            refresh_ciphertext text
                CHECK (refresh_ciphertext IS NULL
                       OR (refresh_ciphertext ~ '{HEX}'
                           AND char_length(refresh_ciphertext) BETWEEN 56 AND 32768)),
            refresh_key_id text CHECK (refresh_key_id IS NULL OR refresh_key_id ~ '{KEY_ID}'),
            created_at timestamptz NOT NULL,
            verified_at timestamptz NOT NULL,
            revoked_reason text CHECK (revoked_reason IS NULL OR revoked_reason IN {REASONS}),
            PRIMARY KEY (tenant_id, credential_id),
            FOREIGN KEY (tenant_id, credential_id)
                REFERENCES execbound.credentials (tenant_id, credential_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id),
            FOREIGN KEY (tenant_id, provider_id)
                REFERENCES execbound.identity_providers (tenant_id, provider_id),
            FOREIGN KEY (tenant_id, link_id)
                REFERENCES execbound.identity_links (tenant_id, link_id),
            CHECK ((refresh_ciphertext IS NULL) = (refresh_key_id IS NULL))
        )
    """)
    _protect("federated_sign_ins")
    # Not partial: a partial index covers no foreign key, which is what
    # `test_foreign_keys_have_covering_indexes` asserts and what a cascade check would read.
    op.execute(
        "CREATE INDEX federated_sign_ins_provider ON execbound.federated_sign_ins "
        "(tenant_id, provider_id)"
    )
    op.execute(
        "CREATE INDEX federated_sign_ins_link ON execbound.federated_sign_ins (tenant_id, link_id)"
    )
    op.execute(
        "CREATE INDEX federated_sign_ins_person ON execbound.federated_sign_ins "
        "(tenant_id, principal_id)"
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
    # A provider, a link and an invitation are current state rather than history, and every
    # audit event about them survives in the chain, so these may be dropped. A live directory
    # credential may not: going back would leave a session standing on a provider that no longer
    # exists and nothing left to recheck it against, so it is refused rather than orphaned.
    live = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM execbound.federated_sign_ins f "
                "JOIN execbound.credentials c USING (tenant_id, credential_id) "
                "WHERE f.revoked_reason IS NULL AND c.revoked_at IS NULL AND c.expires_at > now()"
            )
        )
        .scalar_one()
    )
    if live:
        raise RuntimeError("Cannot downgrade while a directory sign-in is live")
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP TABLE execbound.federated_sign_ins")
    op.execute("DROP TABLE execbound.identity_invitations")
    op.execute("DROP TABLE execbound.identity_links")
    op.execute("DROP TABLE execbound.identity_providers")
