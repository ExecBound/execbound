# SPDX-License-Identifier: AGPL-3.0-only
"""A hosted account holder resets a forgotten password from an emailed link (#678).

Two tables and five definer functions, every one of them used only by the hosted plugin, so
each is created dormant by the revoke convention of `0063_personal_access_tokens` and
`0069_provider_signup`: no grant but the owner's, nothing for PUBLIC, the runtime role or a
Supabase platform role. `execbound hosted-upgrade` grants exactly what the hosted plugin's
`CLAIMS` name, and `check_runtime` refuses any other grant.

`account_recoveries` holds one row per submission of the reset form, in the operator tenant.
A row for an address with no usable account (`NO_ACCOUNT`), or one refused by a limit or the
bot trap (`REFUSED`), holds no account, address, token or version, so the table never says
which addresses were tried. A row that will be mailed holds its account and address; each
send mints a fresh secret (`account_recovery_rekey`), records the account's version at that
moment and gives the link thirty minutes. Only the SHA-256 digest of the link is stored.

`account_messages` is the outbox for the two messages a reset sends, the link and the notice
that the password was reset. Its lease columns are the signup outbox's.

`account_password_recover` completes a reset under the caller's account lock and every
workspace fence of the account. Its factor handling is `user_security_change`'s own `verify`
and `fail` branches, applied to the account's `user_factors` row without a session, with two
additions: a lock already in force, or one the fifth wrong code sets, ends the link. A reset
moves the account's version, revokes every account session and, in every workspace the account
belongs to, every live workspace session and personal access token of its membership.

The functions read and write tables under forced row level security, which binds an owner
without `BYPASSRLS` too, so each sets the account and tenant markers the policies read before
it touches a row, and restores the operator tenant before it returns.
"""

from alembic import op
from sqlalchemy import text

revision = "0085_account_recovery"
down_revision = "0084_reviewers_at_hold"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
TABLES = ("account_messages", "account_recoveries")
SIGNATURES = (
    "account_recovery_request(uuid, uuid, text, text, integer, integer, integer, integer, "
    "timestamptz)",
    "account_recovery_rekey(uuid, text, timestamptz)",
    "account_recovery_check(uuid, text, timestamptz)",
    "account_password_recover(uuid, text, uuid, jsonb, jsonb, uuid, timestamptz)",
    "account_recovery_lapse(timestamptz)",
)

RECOVERIES = """
CREATE TABLE execbound.account_recoveries (
    tenant_id uuid NOT NULL REFERENCES execbound.tenants,
    recovery_id uuid NOT NULL,
    account_id uuid REFERENCES execbound.user_accounts,
    email text CHECK (email IS NULL OR (length(email) BETWEEN 3 AND 254
                                         AND email = lower(email))),
    account_version bigint,
    requested_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('NO_ACCOUNT', 'REFUSED', 'PENDING', 'SENT',
                                         'CONSUMED', 'REPLACED', 'EXPIRED', 'UNDELIVERED')),
    refusal_code text CHECK (refusal_code IS NULL
                             OR refusal_code ~ '^[A-Z][A-Z0-9_]{0,39}$'),
    token_hash text CHECK (token_hash IS NULL OR token_hash ~ '^[0-9a-f]{64}$'),
    sent_at timestamptz,
    expires_at timestamptz,
    failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 5),
    sends integer NOT NULL DEFAULT 0 CHECK (sends >= 0),
    ended_at timestamptz,
    consumed_at timestamptz,
    PRIMARY KEY (tenant_id, recovery_id),
    CONSTRAINT account_recoveries_refused
        CHECK ((state = 'REFUSED') = (refusal_code IS NOT NULL)),
    -- An outcome that mails nothing records nothing about who was asked for.
    CONSTRAINT account_recoveries_unattached
        CHECK (state NOT IN ('NO_ACCOUNT', 'REFUSED')
               OR (account_id IS NULL AND email IS NULL AND token_hash IS NULL
                   AND account_version IS NULL)),
    CONSTRAINT account_recoveries_attached
        CHECK (state IN ('NO_ACCOUNT', 'REFUSED') OR account_id IS NOT NULL),
    -- A live link has its digest, the version it was minted against and at most thirty
    -- minutes from the send that minted it.
    CONSTRAINT account_recoveries_sent
        CHECK (state <> 'SENT' OR (token_hash IS NOT NULL AND account_version IS NOT NULL
                                   AND sent_at IS NOT NULL
                                   AND expires_at <= sent_at + interval '30 minutes'))
)
"""

MESSAGES = """
CREATE TABLE execbound.account_messages (
    tenant_id uuid NOT NULL,
    message_id uuid NOT NULL,
    recovery_id uuid NOT NULL,
    message_class text NOT NULL CHECK (message_class IN ('recovery', 'password_reset')),
    state text NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    next_attempt_at timestamptz NOT NULL,
    lease_until timestamptz,
    lease_token uuid,
    delivered_at timestamptz,
    last_error text CHECK (last_error IS NULL OR last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL,
    -- A notice says so when the reset revoked a personal access token, on every attempt.
    tokens_revoked boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, message_id),
    FOREIGN KEY (tenant_id, recovery_id)
        REFERENCES execbound.account_recoveries (tenant_id, recovery_id),
    UNIQUE (tenant_id, recovery_id, message_class)
)
"""

REQUEST = r"""
CREATE FUNCTION execbound.account_recovery_request(
    p_recovery uuid, p_message uuid, p_email text, p_refusal text, p_ceiling integer,
    p_per_hour integer, p_per_account_hour integer, p_per_account_day integer,
    p_now timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_account execbound.user_accounts%ROWTYPE;
    v_usable boolean := false;
    v_code text;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_recovery IS NULL OR p_message IS NULL
       OR p_ceiling IS NULL OR p_ceiling < 1 OR p_per_hour IS NULL OR p_per_hour < 1
       OR p_per_account_hour IS NULL OR p_per_account_hour < 1
       OR p_per_account_day IS NULL OR p_per_account_day < 1
       OR (p_refusal IS NOT NULL AND p_refusal !~ '^[A-Z][A-Z0-9_]{0,39}$')
       OR (p_refusal IS NULL AND (p_email IS NULL OR p_email <> lower(p_email)
                                  OR length(p_email) NOT BETWEEN 3 AND 254)) THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;

    -- 1. The bot trap, decided by the caller: refused, and nothing about the address read.
    IF p_refusal IS NOT NULL THEN
        v_code := p_refusal;
    ELSE
        -- 2. The account, found by its address the way `locate_account` finds it: the
        --    marker is what `account_email_lookup` reads under forced row level security.
        PERFORM set_config('execbound.sign_in_email', p_email, true);
        SELECT * INTO v_account FROM execbound.user_accounts WHERE email = p_email;
        PERFORM set_config('execbound.sign_in_email', '', true);
        IF FOUND AND v_account.active AND v_account.email_verified_at IS NOT NULL THEN
            -- Only an account that already holds a password can reset one: a first
            -- password keeps its own bar (`0070_first_password`).
            PERFORM set_config('execbound.account_id', v_account.account_id::text, true);
            v_usable := EXISTS (SELECT 1 FROM execbound.user_passwords
                                 WHERE account_id = v_account.account_id);
            PERFORM set_config('execbound.account_id', '', true);
        END IF;
        IF NOT v_usable THEN
            v_code := 'NONE';
        -- 3. The caps, counting only queued `recovery` messages: what reaches an inbox and
        --    spends the relay. Refusals and unknown addresses never count toward them.
        ELSIF (SELECT count(*) FROM execbound.account_messages m
                 JOIN execbound.account_recoveries r
                   ON r.tenant_id = m.tenant_id AND r.recovery_id = m.recovery_id
                WHERE m.tenant_id = v_tenant AND m.message_class = 'recovery'
                  AND r.account_id = v_account.account_id
                  AND m.created_at > p_now - interval '1 hour') >= p_per_account_hour THEN
            v_code := 'ACCOUNT_HOUR_LIMIT';
        ELSIF (SELECT count(*) FROM execbound.account_messages m
                 JOIN execbound.account_recoveries r
                   ON r.tenant_id = m.tenant_id AND r.recovery_id = m.recovery_id
                WHERE m.tenant_id = v_tenant AND m.message_class = 'recovery'
                  AND r.account_id = v_account.account_id
                  AND m.created_at > p_now - interval '1 day') >= p_per_account_day THEN
            v_code := 'ACCOUNT_DAY_LIMIT';
        ELSIF (SELECT count(*) FROM execbound.account_messages m
                WHERE m.tenant_id = v_tenant AND m.message_class = 'recovery'
                  AND m.created_at > p_now - interval '1 hour') >= p_per_hour THEN
            v_code := 'QUEUED_HOUR_LIMIT';
        ELSE
            v_code := 'QUEUED';
        END IF;
    END IF;

    IF v_code <> 'QUEUED' THEN
        -- Past the submission ceiling an outcome that mails nothing records nothing, so the
        -- table cannot be grown without bound; one that would be mailed still records below.
        IF (SELECT count(*) FROM execbound.account_recoveries r
             WHERE r.tenant_id = v_tenant
               AND r.requested_at > p_now - interval '1 hour') >= p_ceiling THEN
            RETURN 'UNRECORDED';
        END IF;
        INSERT INTO execbound.account_recoveries
            (tenant_id, recovery_id, requested_at, state, refusal_code)
        VALUES (v_tenant, p_recovery, p_now,
                CASE WHEN v_code = 'NONE' THEN 'NO_ACCOUNT' ELSE 'REFUSED' END,
                CASE WHEN v_code = 'NONE' THEN NULL ELSE v_code END);
        RETURN v_code;
    END IF;

    -- 4. One live link per account: a newer request replaces every earlier one, and a link
    --    message not yet sent is failed rather than sent with a dead link.
    UPDATE execbound.account_messages m
       SET state = 'FAILED', last_error = 'REPLACED', lease_until = NULL, lease_token = NULL
      FROM execbound.account_recoveries r
     WHERE m.tenant_id = v_tenant AND r.tenant_id = m.tenant_id
       AND r.recovery_id = m.recovery_id AND r.account_id = v_account.account_id
       AND r.state IN ('PENDING', 'SENT') AND m.message_class = 'recovery'
       AND m.state = 'PENDING';
    UPDATE execbound.account_recoveries
       SET state = 'REPLACED', token_hash = NULL, ended_at = p_now
     WHERE tenant_id = v_tenant AND account_id = v_account.account_id
       AND state IN ('PENDING', 'SENT');
    INSERT INTO execbound.account_recoveries
        (tenant_id, recovery_id, account_id, email, requested_at, state)
    VALUES (v_tenant, p_recovery, v_account.account_id, v_account.email, p_now, 'PENDING');
    INSERT INTO execbound.account_messages
        (tenant_id, message_id, recovery_id, message_class, created_at, next_attempt_at)
    VALUES (v_tenant, p_message, p_recovery, 'recovery', p_now, p_now);
    RETURN 'QUEUED';
END $$
"""

REKEY = r"""
CREATE FUNCTION execbound.account_recovery_rekey(
    p_recovery uuid, p_token_hash text, p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_row execbound.account_recoveries%ROWTYPE;
    v_account execbound.user_accounts%ROWTYPE;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_recovery IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    SELECT * INTO v_row FROM execbound.account_recoveries
     WHERE tenant_id = v_tenant AND recovery_id = p_recovery FOR UPDATE;
    IF NOT FOUND OR v_row.state NOT IN ('PENDING', 'SENT') OR v_row.email IS NULL THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    PERFORM set_config('execbound.account_id', v_row.account_id::text, true);
    SELECT * INTO v_account FROM execbound.user_accounts WHERE account_id = v_row.account_id;
    PERFORM set_config('execbound.account_id', '', true);
    IF NOT FOUND OR NOT v_account.active OR v_account.email <> v_row.email THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- Each attempt mints its own secret, so a link from an attempt whose delivery was
    -- uncertain is dead before the next is minted, and binds the account's version now.
    UPDATE execbound.account_recoveries
       SET token_hash = p_token_hash, account_version = v_account.version, sent_at = p_now,
           expires_at = p_now + interval '30 minutes', sends = sends + 1, failures = 0,
           state = 'SENT'
     WHERE tenant_id = v_tenant AND recovery_id = p_recovery;
    RETURN p_now + interval '30 minutes';
END $$
"""

CHECK = r"""
CREATE FUNCTION execbound.account_recovery_check(
    p_recovery uuid, p_token_hash text, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_row execbound.account_recoveries%ROWTYPE;
    v_account execbound.user_accounts%ROWTYPE;
    v_live boolean;
    v_factor boolean;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_recovery IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;
    SELECT * INTO v_row FROM execbound.account_recoveries
     WHERE tenant_id = v_tenant AND recovery_id = p_recovery FOR UPDATE;
    IF NOT FOUND OR v_row.state <> 'SENT' OR v_row.token_hash IS NULL THEN
        RETURN NULL;
    END IF;
    -- A wrong secret counts, and the fifth ends the link. The caller commits the count.
    IF v_row.token_hash <> p_token_hash THEN
        UPDATE execbound.account_recoveries
           SET failures = least(failures + 1, 5),
               state = CASE WHEN failures + 1 >= 5 THEN 'EXPIRED' ELSE state END,
               token_hash = CASE WHEN failures + 1 >= 5 THEN NULL ELSE token_hash END,
               ended_at = CASE WHEN failures + 1 >= 5 THEN p_now ELSE ended_at END
         WHERE tenant_id = v_tenant AND recovery_id = p_recovery;
        RETURN NULL;
    END IF;
    PERFORM set_config('execbound.account_id', v_row.account_id::text, true);
    SELECT * INTO v_account FROM execbound.user_accounts WHERE account_id = v_row.account_id;
    v_live := FOUND AND v_row.expires_at > p_now AND v_row.failures < 5
        AND v_account.active AND v_account.email_verified_at IS NOT NULL
        AND v_account.email = v_row.email AND v_account.version = v_row.account_version
        AND EXISTS (SELECT 1 FROM execbound.user_passwords
                     WHERE account_id = v_row.account_id);
    IF NOT v_live THEN
        -- Expired, or the account's address or sign-in changed since the send: the link is
        -- ended here rather than at its next use.
        PERFORM set_config('execbound.account_id', '', true);
        UPDATE execbound.account_recoveries
           SET state = 'EXPIRED', token_hash = NULL, ended_at = p_now
         WHERE tenant_id = v_tenant AND recovery_id = p_recovery;
        RETURN NULL;
    END IF;
    v_factor := EXISTS (SELECT 1 FROM execbound.user_factors
                         WHERE account_id = v_row.account_id AND enabled_at IS NOT NULL);
    PERFORM set_config('execbound.account_id', '', true);
    RETURN jsonb_build_object('account_id', v_row.account_id, 'email', v_row.email,
                              'factor', v_factor);
END $$
"""

RECOVER = r"""
CREATE FUNCTION execbound.account_password_recover(
    p_recovery uuid, p_token_hash text, p_account uuid, p_factor jsonb, p_password jsonb,
    p_notice uuid, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_operator uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_row execbound.account_recoveries%ROWTYPE;
    v_account execbound.user_accounts%ROWTYPE;
    v_factor execbound.user_factors%ROWTYPE;
    v_method text := 'none';
    v_step bigint;
    v_account_sessions integer;
    v_member record;
    v_sessions jsonb;
    v_tokens jsonb;
    v_tenants jsonb := '[]'::jsonb;
    v_revoked boolean := false;
BEGIN
    IF v_operator IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_recovery IS NULL OR p_account IS NULL OR p_notice IS NULL
       OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
       OR p_factor IS NULL OR jsonb_typeof(p_factor) <> 'object'
       OR p_password IS NULL OR jsonb_typeof(p_password) <> 'object' THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;

    -- 1. The link, under its row lock: live, this secret, this account.
    SELECT * INTO v_row FROM execbound.account_recoveries
     WHERE tenant_id = v_operator AND recovery_id = p_recovery FOR UPDATE;
    IF NOT FOUND OR v_row.state <> 'SENT' OR v_row.token_hash IS NULL THEN
        RETURN jsonb_build_object('result', 'INVALID');
    END IF;
    IF v_row.token_hash <> p_token_hash THEN
        UPDATE execbound.account_recoveries
           SET failures = least(failures + 1, 5),
               state = CASE WHEN failures + 1 >= 5 THEN 'EXPIRED' ELSE state END,
               token_hash = CASE WHEN failures + 1 >= 5 THEN NULL ELSE token_hash END,
               ended_at = CASE WHEN failures + 1 >= 5 THEN p_now ELSE ended_at END
         WHERE tenant_id = v_operator AND recovery_id = p_recovery;
        RETURN jsonb_build_object('result', 'INVALID');
    END IF;
    IF v_row.expires_at <= p_now OR v_row.failures >= 5
       OR v_row.account_id IS DISTINCT FROM p_account THEN
        RETURN jsonb_build_object('result', 'INVALID');
    END IF;

    -- 2. The account it was mailed for, unchanged since the send: active, verified, the same
    --    address and the same version. Any sign-in change since then ends the link.
    PERFORM set_config('execbound.account_id', p_account::text, true);
    SELECT * INTO v_account FROM execbound.user_accounts WHERE account_id = p_account;
    IF NOT FOUND OR NOT v_account.active OR v_account.email_verified_at IS NULL
       OR v_account.email <> v_row.email OR v_account.version <> v_row.account_version
       OR NOT EXISTS (SELECT 1 FROM execbound.user_passwords WHERE account_id = p_account) THEN
        UPDATE execbound.account_recoveries
           SET state = 'EXPIRED', token_hash = NULL, ended_at = p_now
         WHERE tenant_id = v_operator AND recovery_id = p_recovery;
        RETURN jsonb_build_object('result', 'INVALID');
    END IF;

    -- 3. The second factor, when one is enabled: `user_security_change`'s `verify` and `fail`
    --    branches, keyed by the account. A lock in force, or one the fifth wrong code sets,
    --    ends the link, so one link is worth at most five guesses.
    SELECT * INTO v_factor FROM execbound.user_factors WHERE account_id = p_account FOR UPDATE;
    IF FOUND AND v_factor.enabled_at IS NOT NULL THEN
        IF v_factor.locked_until > p_now THEN
            UPDATE execbound.account_recoveries
               SET state = 'EXPIRED', token_hash = NULL, ended_at = p_now
             WHERE tenant_id = v_operator AND recovery_id = p_recovery;
            RETURN jsonb_build_object('result', 'LOCKED');
        END IF;
        IF p_factor->>'method' = 'totp' THEN
            IF jsonb_typeof(p_factor->'step') IS DISTINCT FROM 'number' THEN
                RAISE EXCEPTION 'INVALID_FACTOR';
            END IF;
            v_step := (p_factor->>'step')::bigint;
            IF v_step IS NULL OR v_step <= v_factor.last_step
               OR abs(v_step - floor(extract(epoch FROM p_now) / 30)) > 1 THEN
                RAISE EXCEPTION 'INVALID_FACTOR';
            END IF;
            UPDATE execbound.user_factors SET last_step = v_step, failures = 0,
                   locked_until = NULL
             WHERE account_id = p_account;
            v_method := 'totp';
        ELSIF p_factor->>'method' = 'recovery' THEN
            IF p_factor->>'digest' IS NULL
               OR NOT (v_factor.recovery_hashes ? (p_factor->>'digest')) THEN
                RAISE EXCEPTION 'INVALID_FACTOR';
            END IF;
            UPDATE execbound.user_factors
               SET recovery_hashes = recovery_hashes - (p_factor->>'digest'), failures = 0,
                   locked_until = NULL
             WHERE account_id = p_account;
            v_method := 'recovery';
        ELSIF p_factor->>'method' = 'fail' THEN
            UPDATE execbound.user_factors
               SET failures = CASE WHEN locked_until <= p_now THEN 1
                                   ELSE least(failures + 1, 5) END,
                   locked_until = CASE WHEN locked_until > p_now THEN locked_until
                                       WHEN locked_until <= p_now THEN NULL
                                       WHEN failures >= 4 THEN p_now + interval '15 minutes'
                                       ELSE NULL END
             WHERE account_id = p_account
            RETURNING * INTO v_factor;
            IF v_factor.locked_until > p_now THEN
                UPDATE execbound.account_recoveries
                   SET state = 'EXPIRED', token_hash = NULL, ended_at = p_now
                 WHERE tenant_id = v_operator AND recovery_id = p_recovery;
                RETURN jsonb_build_object('result', 'LOCKED');
            END IF;
            RETURN jsonb_build_object('result', 'FACTOR_REFUSED');
        ELSE
            RAISE EXCEPTION 'INVALID_FACTOR';
        END IF;
    ELSIF p_factor->>'method' IS DISTINCT FROM 'none' THEN
        RAISE EXCEPTION 'INVALID_FACTOR';
    END IF;

    -- 4. The password, the account's version and every account session, keeping none.
    UPDATE execbound.user_passwords
       SET algorithm = p_password->>'algorithm', n = (p_password->>'n')::integer,
           r = (p_password->>'r')::integer, p = (p_password->>'p')::integer,
           dklen = (p_password->>'dklen')::integer, salt = p_password->>'salt',
           hash = p_password->>'hash', updated_at = greatest(p_now, created_at)
     WHERE account_id = p_account;
    UPDATE execbound.user_accounts SET version = version + 1 WHERE account_id = p_account;
    UPDATE execbound.account_sessions SET revoked_at = p_now
     WHERE account_id = p_account AND revoked_at IS NULL;
    GET DIAGNOSTICS v_account_sessions = ROW_COUNT;
    DELETE FROM execbound.account_provider_links
     WHERE account_id = p_account AND consumed_at IS NULL;

    -- 5. Every workspace the account belongs to, active or not: its live sessions and its
    --    live personal access tokens, as `admin_revoke_personal_token` revokes one.
    FOR v_member IN
        SELECT m.tenant_id, m.principal_id, m.active FROM execbound.workspace_memberships m
         WHERE m.account_id = p_account ORDER BY m.tenant_id
    LOOP
        PERFORM set_config('execbound.tenant_id', v_member.tenant_id::text, true);
        WITH ended AS (
            UPDATE execbound.human_sessions h
               SET revoked_at = greatest(p_now, h.created_at)
             WHERE h.tenant_id = v_member.tenant_id AND h.revoked_at IS NULL
               AND h.expires_at > p_now
               AND (h.account_id = p_account OR h.principal_id = v_member.principal_id)
            RETURNING h.session_id)
        SELECT coalesce(jsonb_agg(session_id::text ORDER BY session_id), '[]'::jsonb)
          INTO v_sessions FROM ended;
        WITH revoked AS (
            UPDATE execbound.personal_access_tokens k
               SET revoked_at = greatest(p_now, k.created_at), revoked_by = v_member.principal_id
             WHERE k.tenant_id = v_member.tenant_id AND k.principal_id = v_member.principal_id
               AND k.revoked_at IS NULL AND k.deleted_at IS NULL AND k.expires_at > p_now
            RETURNING k.token_id, k.credential_id),
        revoked_credentials AS (
            UPDATE execbound.credentials c SET revoked_at = p_now
              FROM revoked
             WHERE c.tenant_id = v_member.tenant_id AND c.credential_id = revoked.credential_id
               AND c.revoked_at IS NULL
            RETURNING c.credential_id)
        SELECT coalesce(jsonb_agg(token_id::text ORDER BY token_id), '[]'::jsonb)
          INTO v_tokens FROM revoked;
        v_revoked := v_revoked OR jsonb_array_length(v_tokens) > 0;
        IF v_member.active OR jsonb_array_length(v_sessions) > 0
           OR jsonb_array_length(v_tokens) > 0 THEN
            v_tenants := v_tenants || jsonb_build_array(jsonb_build_object(
                'tenant_id', v_member.tenant_id, 'principal_id', v_member.principal_id,
                'sessions', v_sessions, 'tokens', v_tokens));
        END IF;
    END LOOP;
    PERFORM set_config('execbound.tenant_id', v_operator::text, true);

    -- 6. The link is spent, every other live link of the account ends, and the notice is
    --    queued under the id the caller generated.
    UPDATE execbound.account_recoveries
       SET state = 'CONSUMED', token_hash = NULL, failures = 0, consumed_at = p_now,
           ended_at = p_now
     WHERE tenant_id = v_operator AND recovery_id = p_recovery;
    UPDATE execbound.account_messages m
       SET state = 'FAILED', last_error = 'REPLACED', lease_until = NULL, lease_token = NULL
      FROM execbound.account_recoveries r
     WHERE m.tenant_id = v_operator AND r.tenant_id = m.tenant_id
       AND r.recovery_id = m.recovery_id AND r.account_id = p_account
       AND r.state IN ('PENDING', 'SENT') AND m.message_class = 'recovery'
       AND m.state = 'PENDING';
    UPDATE execbound.account_recoveries
       SET state = 'REPLACED', token_hash = NULL, ended_at = p_now
     WHERE tenant_id = v_operator AND account_id = p_account AND state IN ('PENDING', 'SENT');
    INSERT INTO execbound.user_security_events(account_id, kind, occurred_at)
    VALUES (p_account, 'password_reset', p_now);
    INSERT INTO execbound.account_messages
        (tenant_id, message_id, recovery_id, message_class, created_at, next_attempt_at,
         tokens_revoked)
    VALUES (v_operator, p_notice, p_recovery, 'password_reset', p_now, p_now, v_revoked);
    RETURN jsonb_build_object('result', 'RESET', 'method', v_method,
                              'account_sessions', v_account_sessions, 'tenants', v_tenants);
END $$
"""

LAPSE = r"""
CREATE FUNCTION execbound.account_recovery_lapse(p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_expired integer;
    v_undelivered integer;
    v_cleared integer;
    v_deleted integer;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    UPDATE execbound.account_recoveries
       SET state = 'EXPIRED', token_hash = NULL, ended_at = p_now
     WHERE tenant_id = v_tenant AND state = 'SENT' AND expires_at <= p_now;
    GET DIAGNOSTICS v_expired = ROW_COUNT;
    UPDATE execbound.account_recoveries r
       SET state = 'UNDELIVERED', ended_at = p_now
     WHERE r.tenant_id = v_tenant AND r.state = 'PENDING'
       AND EXISTS (SELECT 1 FROM execbound.account_messages m
                    WHERE m.tenant_id = r.tenant_id AND m.recovery_id = r.recovery_id
                      AND m.message_class = 'recovery' AND m.state = 'FAILED');
    GET DIAGNOSTICS v_undelivered = ROW_COUNT;
    -- An ended row keeps its address for a day, and for as long after that as a message of
    -- its own still has to reach it: a notice the relay's daily limit deferred.
    UPDATE execbound.account_recoveries r SET email = NULL
     WHERE r.tenant_id = v_tenant AND r.email IS NOT NULL
       AND r.state IN ('CONSUMED', 'REPLACED', 'EXPIRED', 'UNDELIVERED')
       AND r.ended_at <= p_now - interval '1 day'
       AND NOT EXISTS (SELECT 1 FROM execbound.account_messages m
                        WHERE m.tenant_id = r.tenant_id AND m.recovery_id = r.recovery_id
                          AND m.state IN ('PENDING', 'IN_FLIGHT'));
    GET DIAGNOSTICS v_cleared = ROW_COUNT;
    DELETE FROM execbound.account_messages m USING execbound.account_recoveries r
     WHERE m.tenant_id = v_tenant AND r.tenant_id = m.tenant_id
       AND r.recovery_id = m.recovery_id AND r.requested_at <= p_now - interval '30 days';
    DELETE FROM execbound.account_recoveries
     WHERE tenant_id = v_tenant AND requested_at <= p_now - interval '30 days';
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN jsonb_build_object('expired', v_expired, 'undelivered', v_undelivered,
                              'cleared', v_cleared, 'deleted', v_deleted);
END $$
"""


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(RECOVERIES)
    op.execute(MESSAGES)
    # The submission ceiling counts an hour of rows; the per-account caps join each queued
    # message to its row by account; the drain walks what is due.
    op.execute(
        "CREATE INDEX account_recoveries_requested ON execbound.account_recoveries "
        "(tenant_id, requested_at)"
    )
    # Led by the account, so it also covers the foreign key to `user_accounts`.
    op.execute(
        "CREATE INDEX account_recoveries_account ON execbound.account_recoveries "
        "(account_id, tenant_id, requested_at)"
    )
    op.execute(
        "CREATE INDEX account_messages_class ON execbound.account_messages "
        "(tenant_id, message_class, created_at)"
    )
    op.execute(
        "CREATE INDEX account_messages_pending ON execbound.account_messages "
        "(tenant_id, next_attempt_at, message_id) WHERE state IN ('PENDING', 'IN_FLIGHT')"
    )
    roles = [role for role in ("anon", "authenticated", "service_role") if role_exists(role)]
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON execbound.{table} "
            f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
        )
        # Born dormant: no grant but the owner's, so a runtime with no hosted plugin can
        # neither read a row nor learn that a reset was ever asked for.
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    for body in (REQUEST, REKEY, CHECK, RECOVER, LAPSE):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")


def downgrade() -> None:
    # Pending links stop working; nothing else references either table. The account's
    # `password_reset` security events stay: they are history the bell still labels.
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP TABLE execbound.account_messages")
    op.execute("DROP TABLE execbound.account_recoveries")
