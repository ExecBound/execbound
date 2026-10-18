"""Teammate invitations: tenant-bound, expiring, single-use links that add a membership.

An invitation lives in the workspace that sent it and names one normalized address, the
inviter and the proposed role grants. Its link secret is minted inside the send, so only
the latest delivered link works. Acceptance re-checks everything in one transaction and
applies the grants through `access_change` as the inviter, so the inviter's current
authority decides, not the authority they had when they clicked Invite.

Delivery must reach workspaces that no jobs token names. `workspace_invitation_due` lists
due messages across tenants through a SELECT policy granted only to the role that runs
this migration, which is the role every definer function here runs as; the runtime role
sees its own tenant's rows and nothing else.
"""

from alembic import op
from sqlalchemy import text

revision = "0059_workspace_invitations"
down_revision = "0058_api_key_numbers"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
DELIVERY = (
    "state",
    "attempts",
    "next_attempt_at",
    "lease_until",
    "lease_token",
    "delivered_at",
    "last_error",
)
SIGNATURES = (
    "workspace_invitation_create(uuid, uuid, text, jsonb, uuid, timestamptz)",
    "workspace_invitation_revoke(uuid, uuid, timestamptz)",
    "workspace_invitation_resend(uuid, uuid, timestamptz)",
    "workspace_invitation_due(timestamptz, integer)",
    "workspace_invitation_rekey(uuid, text, timestamptz)",
    "workspace_invitation_check(uuid, text, timestamptz)",
    "workspace_invitation_accept(uuid, text, uuid, uuid, jsonb, timestamptz)",
)

TABLES = """
CREATE TABLE execbound.workspace_invitations (
    tenant_id uuid NOT NULL REFERENCES execbound.tenants,
    invitation_id uuid NOT NULL,
    email text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    inviter_id uuid NOT NULL,
    grants jsonb NOT NULL CHECK (jsonb_typeof(grants) = 'array'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    token_hash text CHECK (token_hash IS NULL OR token_hash ~ '^[0-9a-f]{64}$'),
    generation integer NOT NULL DEFAULT 0 CHECK (generation >= 0),
    failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 5),
    sends integer NOT NULL DEFAULT 1 CHECK (sends BETWEEN 1 AND 5),
    state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACCEPTED', 'REVOKED')),
    accepted_at timestamptz,
    accepted_principal_id uuid,
    accepted_account_id uuid,
    revoked_at timestamptz,
    revoked_by uuid,
    PRIMARY KEY (tenant_id, invitation_id),
    FOREIGN KEY (tenant_id, inviter_id) REFERENCES execbound.principals,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days'),
    CHECK ((state = 'ACCEPTED') = (accepted_at IS NOT NULL)
           AND (accepted_at IS NULL) = (accepted_principal_id IS NULL)
           AND (accepted_at IS NULL) = (accepted_account_id IS NULL)),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX workspace_invitations_pending
    ON execbound.workspace_invitations (tenant_id, email) WHERE state = 'PENDING';
CREATE INDEX workspace_invitations_inviter
    ON execbound.workspace_invitations (tenant_id, inviter_id);
CREATE TABLE execbound.workspace_invitation_messages (
    tenant_id uuid NOT NULL,
    message_id uuid NOT NULL,
    invitation_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    next_attempt_at timestamptz NOT NULL,
    lease_until timestamptz,
    lease_token uuid,
    delivered_at timestamptz,
    last_error text CHECK (last_error IS NULL OR last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    PRIMARY KEY (tenant_id, message_id),
    UNIQUE (tenant_id, invitation_id),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES execbound.workspace_invitations
);
CREATE INDEX workspace_invitation_messages_due
    ON execbound.workspace_invitation_messages (next_attempt_at)
    WHERE state IN ('PENDING', 'IN_FLIGHT');
"""

# The tenant, the clock and the acting administrator, shared by every administrator path.
# The actor must be an active principal of this active tenant holding `access.manage` now.
ACTOR_CHECK = r"""
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active)
       OR NOT EXISTS (SELECT 1 FROM execbound.principals p WHERE p.tenant_id = v_tenant
                       AND p.principal_id = p_actor AND p.active)
       OR NOT execbound.access_has_permission(p_actor, 'access.manage', NULL, false) THEN
        RAISE EXCEPTION 'FORBIDDEN';
    END IF;
"""

GRANT_CHECK = r"""
    -- The same shape rules `access_change` enforces, applied at creation so a bad grant is
    -- refused while the administrator is still on the page.
    IF p_grants IS NULL OR jsonb_typeof(p_grants) <> 'array'
       OR jsonb_array_length(p_grants) NOT BETWEEN 1 AND 20 THEN
        RAISE EXCEPTION 'INVALID_ROLES';
    END IF;
    FOR v_item IN SELECT value FROM jsonb_array_elements(p_grants) LOOP
        IF jsonb_typeof(v_item) <> 'object' OR (v_item - 'role' - 'space_id') <> '{}'::jsonb
           OR v_item->>'role' IS NULL OR v_item->>'role' NOT IN
              ('administrator', 'policy_manager', 'approver', 'viewer') THEN
            RAISE EXCEPTION 'INVALID_ROLE';
        END IF;
        -- Absent, JSON null, or a UUID string in the 8-4-4-4-12 form in any case. Anything
        -- else is refused here, never left to a cast error.
        IF coalesce(jsonb_typeof(v_item->'space_id'), 'null') <> 'null'
           AND (jsonb_typeof(v_item->'space_id') <> 'string'
                OR lower(v_item->>'space_id')
                   !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
        v_space := lower(v_item->>'space_id')::uuid;
        IF v_item->>'role' = 'administrator' AND v_space IS NOT NULL THEN
            RAISE EXCEPTION 'INVALID_ROLE_SCOPE';
        END IF;
        IF v_space IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM execbound.spaces s WHERE s.tenant_id = v_tenant
               AND s.space_id = v_space AND s.archived_at IS NULL) THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
    END LOOP;
    -- Stored in one canonical shape, every Space id lowercase, so the ids in the grants are
    -- the keys `workspace_invitation_check` names the Spaces by.
    SELECT jsonb_agg(jsonb_build_object('role', g.value->>'role',
                                        'space_id', lower(g.value->>'space_id'))
                     ORDER BY g.ordinality)
      INTO v_grants FROM jsonb_array_elements(p_grants) WITH ORDINALITY g;
    -- `access_change` stores each (role, Space) pair once and answers a repeat CONFLICT, so a
    -- repeated pair would make an invitation nobody could ever accept.
    IF (SELECT count(*) FROM (SELECT DISTINCT g->>'role', g->>'space_id'
                                FROM jsonb_array_elements(v_grants) g) d)
       <> jsonb_array_length(v_grants) THEN
        RAISE EXCEPTION 'INVALID_ROLES';
    END IF;
"""

CREATE = (
    r"""
CREATE FUNCTION execbound.workspace_invitation_create(
    p_actor uuid, p_invitation uuid, p_email text, p_grants jsonb, p_message uuid,
    p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_item jsonb;
    v_space uuid;
    v_grants jsonb;
    v_expires timestamptz;
BEGIN
    IF v_tenant IS NULL OR p_actor IS NULL OR p_invitation IS NULL OR p_message IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
"""
    + ACTOR_CHECK
    + r"""
    IF p_email IS NULL OR p_email <> lower(btrim(p_email)) OR length(p_email) NOT BETWEEN 3 AND 254
       OR p_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' THEN
        RAISE EXCEPTION 'INVALID_EMAIL';
    END IF;
"""
    + GRANT_CHECK
    + r"""
    -- Already here: an active principal of this tenant holds the address, or an account
    -- holding it has an active membership here whose principal is active. A member removed
    -- by deactivating their principal may be invited back. The account lookup uses the
    -- sign_in_email policy.
    IF EXISTS (SELECT 1 FROM execbound.principals p WHERE p.tenant_id = v_tenant
                AND p.email = p_email AND p.active) THEN
        RAISE EXCEPTION 'ALREADY_MEMBER';
    END IF;
    PERFORM set_config('execbound.sign_in_email', p_email, true);
    IF EXISTS (SELECT 1 FROM execbound.user_accounts a
                JOIN execbound.workspace_memberships m ON m.account_id = a.account_id
                JOIN execbound.principals p
                  ON p.tenant_id = m.tenant_id AND p.principal_id = m.principal_id
               WHERE a.email = p_email AND m.tenant_id = v_tenant AND m.active AND p.active) THEN
        PERFORM set_config('execbound.sign_in_email', '', true);
        RAISE EXCEPTION 'ALREADY_MEMBER';
    END IF;
    PERFORM set_config('execbound.sign_in_email', '', true);
    v_expires := p_now + interval '7 days';
    BEGIN
        INSERT INTO execbound.workspace_invitations
            (tenant_id, invitation_id, email, inviter_id, grants, created_at, expires_at)
        VALUES (v_tenant, p_invitation, p_email, p_actor, v_grants, p_now, v_expires);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'INVITATION_PENDING';
    END;
    INSERT INTO execbound.workspace_invitation_messages
        (tenant_id, message_id, invitation_id, created_at, next_attempt_at)
    VALUES (v_tenant, p_message, p_invitation, p_now, p_now);
    RETURN v_expires;
END $$
"""
)

REVOKE = (
    r"""
CREATE FUNCTION execbound.workspace_invitation_revoke(
    p_actor uuid, p_invitation uuid, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL OR p_actor IS NULL OR p_invitation IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
"""
    + ACTOR_CHECK
    + r"""
    -- The row lock serializes this against an acceptance of the same invitation: whichever
    -- commits first decides, and the other sees its outcome.
    PERFORM 1 FROM execbound.workspace_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND';
    END IF;
    -- The token digest stays, so the recipient's link can still say it was revoked.
    UPDATE execbound.workspace_invitations
       SET state = 'REVOKED', revoked_at = p_now, revoked_by = p_actor
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation AND state = 'PENDING';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- A send not yet started never starts. One already in flight finds the invitation no
    -- longer pending when it tries to mint its link, and settles itself.
    UPDATE execbound.workspace_invitation_messages
       SET state = 'FAILED', last_error = 'REVOKED'
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation AND state = 'PENDING';
END $$
"""
)

RESEND = (
    r"""
CREATE FUNCTION execbound.workspace_invitation_resend(
    p_actor uuid, p_invitation uuid, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_invitation execbound.workspace_invitations%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_actor IS NULL OR p_invitation IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
"""
    + ACTOR_CHECK
    + r"""
    SELECT * INTO v_invitation FROM execbound.workspace_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND';
    END IF;
    -- Resend never extends the expiry, so an expired invitation is a new invitation.
    IF v_invitation.state <> 'PENDING' OR v_invitation.expires_at <= p_now THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- Bounded in number and spacing, and never while a link is on its way.
    IF v_invitation.sends >= 5 OR EXISTS (
        SELECT 1 FROM execbound.workspace_invitation_messages m
         WHERE m.tenant_id = v_tenant AND m.invitation_id = p_invitation
           AND (m.state IN ('PENDING', 'IN_FLIGHT')
                OR m.delivered_at > p_now - interval '2 minutes')
    ) THEN
        RAISE EXCEPTION 'RESEND_LIMIT';
    END IF;
    UPDATE execbound.workspace_invitations SET sends = sends + 1
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    UPDATE execbound.workspace_invitation_messages
       SET state = 'PENDING', attempts = 0, next_attempt_at = p_now,
           lease_until = NULL, lease_token = NULL, delivered_at = NULL, last_error = NULL
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
END $$
"""
)

DUE = r"""
CREATE FUNCTION execbound.workspace_invitation_due(p_now timestamptz, p_limit integer)
RETURNS TABLE(tenant_id uuid, message_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.tenant_id, m.message_id FROM execbound.workspace_invitation_messages m
     WHERE ((m.state = 'PENDING' AND m.next_attempt_at <= p_now)
            OR (m.state = 'IN_FLIGHT' AND m.lease_until <= p_now))
       AND p_limit BETWEEN 1 AND 200
     ORDER BY m.next_attempt_at, m.message_id
     LIMIT p_limit
$$
"""

REKEY = r"""
CREATE FUNCTION execbound.workspace_invitation_rekey(
    p_invitation uuid, p_token_hash text, p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_expires timestamptz;
BEGIN
    IF v_tenant IS NULL OR p_invitation IS NULL OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- Only while the invitation still waits for its person: accepting, revoking or expiring
    -- it stops every later send from minting a link. The expiry is the creation's, unchanged.
    UPDATE execbound.workspace_invitations
       SET generation = generation + 1, token_hash = p_token_hash, failures = 0
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation AND state = 'PENDING'
       AND expires_at > p_now
    RETURNING expires_at INTO v_expires;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    RETURN v_expires;
END $$
"""

CHECK = r"""
CREATE FUNCTION execbound.workspace_invitation_check(
    p_invitation uuid, p_token_hash text, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_invitation execbound.workspace_invitations%ROWTYPE;
    v_workspace text;
    v_inviter text;
    v_spaces jsonb;
BEGIN
    IF v_tenant IS NULL OR p_invitation IS NULL OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_invitation FROM execbound.workspace_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND OR v_invitation.token_hash IS NULL OR v_invitation.failures >= 5 THEN
        RETURN NULL;
    END IF;
    -- A wrong guess counts and the function returns normally, so the count commits.
    IF v_invitation.token_hash <> p_token_hash THEN
        UPDATE execbound.workspace_invitations SET failures = failures + 1
         WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
        RETURN NULL;
    END IF;
    SELECT t.name INTO v_workspace FROM execbound.tenants t WHERE t.tenant_id = v_tenant;
    SELECT coalesce(p.label, p.email) INTO v_inviter FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.principal_id = v_invitation.inviter_id;
    SELECT coalesce(jsonb_object_agg(s.space_id::text, s.name), '{}'::jsonb) INTO v_spaces
      FROM execbound.spaces s
     WHERE s.tenant_id = v_tenant AND s.space_id IN (
         SELECT (g->>'space_id')::uuid FROM jsonb_array_elements(v_invitation.grants) g
          WHERE g->>'space_id' IS NOT NULL);
    RETURN jsonb_build_object(
        'state', CASE WHEN v_invitation.state = 'PENDING' AND v_invitation.expires_at <= p_now
                      THEN 'EXPIRED' ELSE v_invitation.state END,
        'email', v_invitation.email,
        'workspace', v_workspace,
        'grants', v_invitation.grants,
        'space_names', v_spaces,
        'inviter_label', v_inviter,
        'expires_at', v_invitation.expires_at);
END $$
"""

ACCEPT = r"""
CREATE FUNCTION execbound.workspace_invitation_accept(
    p_invitation uuid, p_token_hash text, p_principal uuid, p_account uuid, p_password jsonb,
    p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_signed_in uuid := nullif(current_setting('execbound.account_id', true), '')::uuid;
    v_invitation execbound.workspace_invitations%ROWTYPE;
    v_account execbound.user_accounts%ROWTYPE;
    v_account_id uuid;
    v_version bigint;
    v_changed jsonb;
    v_former boolean;
    v_rejoin boolean := false;
BEGIN
    -- Caller order: account_lock, tenant fence, then this; a new address takes the fence first.
    -- 1. The arguments and the clock. Exactly one proof of the person: a new password for a
    --    new account, or an account the caller has already authenticated in this
    --    transaction. Never both, never neither.
    IF v_tenant IS NULL OR p_invitation IS NULL OR p_principal IS NULL
       OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF (p_password IS NULL) = (v_signed_in IS NULL)
       OR (p_password IS NOT NULL AND p_account IS NULL) THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;

    -- 2. The invitation, locked, and the link. A wrong guess counts and the function
    --    returns normally, so the count commits.
    SELECT * INTO v_invitation FROM execbound.workspace_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND OR v_invitation.token_hash IS NULL OR v_invitation.failures >= 5 THEN
        RETURN NULL;
    END IF;
    IF v_invitation.token_hash <> p_token_hash THEN
        UPDATE execbound.workspace_invitations SET failures = failures + 1
         WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
        RETURN NULL;
    END IF;

    -- 3. Already accepted: a retry by the same person finds the one committed outcome. A
    --    consumed link never mints anything for a password, and never for another account.
    IF v_invitation.state = 'ACCEPTED' THEN
        IF p_password IS NOT NULL OR v_invitation.accepted_account_id = v_signed_in THEN
            RETURN jsonb_build_object('outcome', 'ALREADY');
        END IF;
        RAISE EXCEPTION 'INVALID_TOKEN';
    END IF;

    -- 4. Revoked or expired.
    IF v_invitation.state = 'REVOKED' THEN
        RAISE EXCEPTION 'INVITATION_REVOKED';
    END IF;
    IF v_invitation.expires_at <= p_now THEN
        RAISE EXCEPTION 'INVALID_TOKEN';
    END IF;

    -- 5. The workspace, and the inviter's authority as it stands now.
    IF NOT EXISTS (SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active)
    THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM execbound.principals p WHERE p.tenant_id = v_tenant
                    AND p.principal_id = v_invitation.inviter_id AND p.active)
       OR NOT execbound.access_has_permission(
           v_invitation.inviter_id, 'access.manage', NULL, false) THEN
        RAISE EXCEPTION 'FORBIDDEN';
    END IF;

    -- 6. The account.
    IF p_password IS NOT NULL THEN
        -- A new account only for an address nobody signs in with yet: not one an account
        -- holds, and not one an active person set up before accounts existed holds. The
        -- marker is what the `sign_in_email` policies read, so both lookups see every
        -- tenant under forced row-level security.
        PERFORM set_config('execbound.sign_in_email', v_invitation.email, true);
        IF EXISTS (SELECT 1 FROM execbound.user_accounts WHERE email = v_invitation.email)
           OR EXISTS (SELECT 1 FROM execbound.principals p
                       WHERE p.email = v_invitation.email AND p.active
                         AND p.kind IN ('ADMIN', 'HUMAN_APPROVER')) THEN
            RAISE EXCEPTION 'ACCOUNT_EXISTS';
        END IF;
        PERFORM set_config('execbound.sign_in_email', '', true);
        PERFORM set_config('execbound.account_id', p_account::text, true);
        BEGIN
            -- The link proved the mailbox. No Community allocation: an invited-only account
            -- may still create its own workspace later through verified signup.
            INSERT INTO execbound.user_accounts(account_id, email, email_verified_at)
            VALUES (p_account, v_invitation.email, p_now);
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION 'ACCOUNT_EXISTS';
        END;
        INSERT INTO execbound.user_passwords
            (account_id, algorithm, n, r, p, dklen, salt, hash, created_at, updated_at)
        VALUES (p_account, p_password->>'algorithm', (p_password->>'n')::integer,
                (p_password->>'r')::integer, (p_password->>'p')::integer,
                (p_password->>'dklen')::integer, p_password->>'salt', p_password->>'hash',
                p_now, p_now);
        v_account_id := p_account;
    ELSE
        SELECT * INTO v_account FROM execbound.user_accounts
         WHERE account_id = v_signed_in FOR UPDATE;
        IF NOT FOUND OR NOT v_account.active OR v_account.email <> v_invitation.email THEN
            RAISE EXCEPTION 'ACCOUNT_MISMATCH';
        END IF;
        v_account_id := v_signed_in;
        -- One membership per account and workspace. While its principal is active the
        -- account is already here; once that principal was deactivated (removal), the
        -- membership is re-pointed at the new principal below.
        SELECT p.active INTO v_former FROM execbound.workspace_memberships m
          JOIN execbound.principals p
            ON p.tenant_id = m.tenant_id AND p.principal_id = m.principal_id
         WHERE m.account_id = v_account_id AND m.tenant_id = v_tenant;
        IF FOUND AND v_former THEN
            RAISE EXCEPTION 'ALREADY_MEMBER';
        END IF;
        v_rejoin := FOUND;
        -- The link proved the mailbox, so a legacy address becomes a verified one.
        UPDATE execbound.user_accounts
           SET email_verified_at = coalesce(email_verified_at, p_now)
         WHERE account_id = v_account_id;
    END IF;
    SELECT version INTO v_version FROM execbound.user_accounts WHERE account_id = v_account_id;

    -- 7. The principal. The address is its email unless another principal anywhere holds
    --    it (`principals_email` is global); then the label names the person instead, cut
    --    to the label's 80 characters.
    INSERT INTO execbound.principals(tenant_id, principal_id, kind)
    VALUES (v_tenant, p_principal, 'HUMAN_APPROVER');
    BEGIN
        UPDATE execbound.principals SET email = v_invitation.email
         WHERE tenant_id = v_tenant AND principal_id = p_principal;
    EXCEPTION WHEN unique_violation THEN
        -- For a new account that holder committed after the check above, so it is checked
        -- again: an active person is the same refusal, and an inactive one is not.
        IF p_password IS NOT NULL THEN
            PERFORM set_config('execbound.sign_in_email', v_invitation.email, true);
            IF EXISTS (SELECT 1 FROM execbound.principals p
                        WHERE p.email = v_invitation.email AND p.active
                          AND p.kind IN ('ADMIN', 'HUMAN_APPROVER')) THEN
                RAISE EXCEPTION 'ACCOUNT_EXISTS';
            END IF;
            PERFORM set_config('execbound.sign_in_email', '', true);
        END IF;
        UPDATE execbound.principals SET label = left(v_invitation.email, 80)
         WHERE tenant_id = v_tenant AND principal_id = p_principal;
    END;

    -- 8. The grants, applied as the inviter through the one implementation of the grant
    --    rules. It fences the tenant, re-checks the inviter and every Space, and handles a
    --    promotion to administrator.
    v_changed := execbound.access_change(
        v_invitation.inviter_id, 'set_user_roles', p_principal,
        jsonb_build_object('grants', v_invitation.grants));

    -- 9. The membership. A removed member's row moves to the new principal and its version
    --    moves on, so no session minted for the old one validates; the old principal stays
    --    deactivated with its history.
    IF v_rejoin THEN
        UPDATE execbound.workspace_memberships
           SET principal_id = p_principal, active = true, version = version + 1
         WHERE account_id = v_account_id AND tenant_id = v_tenant;
    ELSE
        BEGIN
            INSERT INTO execbound.workspace_memberships(account_id, tenant_id, principal_id)
            VALUES (v_account_id, v_tenant, p_principal);
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION 'ALREADY_MEMBER';
        END;
    END IF;

    -- 10. The one outcome, and no further sends.
    UPDATE execbound.workspace_invitations
       SET state = 'ACCEPTED', accepted_at = p_now, accepted_principal_id = p_principal,
           accepted_account_id = v_account_id
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    UPDATE execbound.workspace_invitation_messages
       SET state = 'FAILED', last_error = 'ACCEPTED'
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation AND state = 'PENDING';

    RETURN jsonb_build_object(
        'outcome', 'ACCEPTED', 'principal_id', p_principal, 'account_id', v_account_id,
        'account_version', v_version, 'grants', v_invitation.grants,
        'inviter_id', v_invitation.inviter_id, 'changed', v_changed);
END $$
"""


def protect(table: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON execbound.{table} "
        f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
    )
    op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC, execbound_app")
    for role in ("anon", "authenticated", "service_role"):
        if role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(TABLES)
    for table in ("workspace_invitations", "workspace_invitation_messages"):
        protect(table)
    # The drain's cross-tenant read. Granted to the role running this migration, which owns
    # every definer function below; the runtime role never matches it.
    op.execute(
        "CREATE POLICY owner_drain ON execbound.workspace_invitation_messages "
        "FOR SELECT TO CURRENT_USER USING (true)"
    )
    op.execute(
        "GRANT UPDATE (" + ", ".join(DELIVERY) + ") "
        "ON execbound.workspace_invitation_messages TO execbound_app"
    )
    for body in (CREATE, REVOKE, RESEND, DUE, REKEY, CHECK, ACCEPT):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    # An owner that does not bypass row security sees no tenant's invitation unfenced, so
    # FORCE is lifted around the count and put back before anything else happens.
    op.execute("ALTER TABLE execbound.workspace_invitations NO FORCE ROW LEVEL SECURITY")
    populated = (
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM execbound.workspace_invitations)"))
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.workspace_invitations FORCE ROW LEVEL SECURITY")
    if populated:
        raise RuntimeError(
            "Teammate invitations require a verified full restore; lossy downgrade refused"
        )
    for signature in reversed(SIGNATURES):
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP POLICY owner_drain ON execbound.workspace_invitation_messages")
    op.execute("DROP TABLE execbound.workspace_invitation_messages")
    op.execute("DROP TABLE execbound.workspace_invitations")
