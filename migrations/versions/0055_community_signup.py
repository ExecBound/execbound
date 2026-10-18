"""Verified Community signup: verification links, on-demand workspaces and workspace slugs.

A request that passes admission is sent a verification link instead of a seeded slot's
invitation. The link's secret is minted inside the send, exactly as an invitation code is, so
only the most recent delivered link works. Completing it runs `community_provision`, which
creates the account (or uses the signed-in one), the tenant, its first ADMIN, its Default
space, the membership and the consumed Community allocation in one transaction, and records
the request's one outcome so a retry finds it instead of making another.

The runtime gains EXECUTE on four definer functions and no table write. Display names stop
being globally unique; a generated slug is. Dormancy measures a provisioned workspace from
its provisioning, as it measures a claimed slot from its claim.
"""

from alembic import op
from sqlalchemy import text

revision = "0055_community_signup"
down_revision = "0054_account_memberships"
branch_labels = None
depends_on = None

STATES = "('QUEUED', 'INVITED', 'CLAIMED', 'EXPIRED', 'REFUSED', 'VERIFYING', 'PROVISIONED')"
OLD_STATES = "('QUEUED', 'INVITED', 'CLAIMED', 'EXPIRED', 'REFUSED')"
CLASSES = "('invitation', 'waitlist', 'lifecycle', 'verification')"
OLD_CLASSES = "('invitation', 'waitlist', 'lifecycle')"
SIGNATURES = (
    "signup_verify_queue(uuid, uuid, timestamptz)",
    "signup_verify_rekey(uuid, text, timestamptz)",
    "signup_verify_check(uuid, text, timestamptz)",
    "community_provision(uuid, text, uuid, uuid, uuid, text, text, jsonb, integer, timestamptz)",
)

QUEUE = r"""
CREATE FUNCTION execbound.signup_verify_queue(p_request uuid, p_message uuid, p_now timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_request execbound.signup_requests%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_request IS NULL OR p_message IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_request FROM execbound.signup_requests r
     WHERE r.tenant_id = v_tenant AND r.request_id = p_request FOR UPDATE;
    IF NOT FOUND OR v_request.email IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF v_request.state = 'QUEUED' THEN
        -- A new admission cycle (including a re-admission after CAPACITY returned the
        -- request here) starts its own send count; it never inherits an earlier cycle's.
        UPDATE execbound.signup_requests
           SET state = 'VERIFYING', verifying_at = p_now, verify_sends = 1,
               verify_token_hash = NULL, verify_expires_at = NULL, verify_failures = 0
         WHERE tenant_id = v_tenant AND request_id = p_request;
    ELSIF v_request.state = 'VERIFYING' THEN
        -- A resend. Bounded in number and spacing, and never while a link is on its way.
        IF v_request.verify_sends >= 5 OR EXISTS (
            SELECT 1 FROM execbound.signup_messages m
             WHERE m.tenant_id = v_tenant AND m.request_id = p_request
               AND m.message_class = 'verification'
               AND (m.state IN ('PENDING', 'IN_FLIGHT')
                    OR m.delivered_at > p_now - interval '2 minutes')
        ) THEN
            RAISE EXCEPTION 'RESEND_LIMIT';
        END IF;
        UPDATE execbound.signup_requests SET verify_sends = verify_sends + 1
         WHERE tenant_id = v_tenant AND request_id = p_request;
    ELSE
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    INSERT INTO execbound.signup_messages
        (tenant_id, message_id, request_id, message_class, created_at, next_attempt_at)
    VALUES (v_tenant, p_message, p_request, 'verification', p_now, p_now)
    ON CONFLICT (tenant_id, request_id, message_class) DO UPDATE
       SET state = 'PENDING', attempts = 0, next_attempt_at = EXCLUDED.next_attempt_at,
           lease_until = NULL, lease_token = NULL, delivered_at = NULL, last_error = NULL;
    RETURN 'VERIFYING';
END $$
"""

REKEY = r"""
CREATE FUNCTION execbound.signup_verify_rekey(p_request uuid, p_token_hash text, p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_expires timestamptz;
BEGIN
    IF v_tenant IS NULL OR p_request IS NULL OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- Only while the request is still waiting for its person: completing or expiring it
    -- stops every later send from minting a link.
    UPDATE execbound.signup_requests
       SET verify_generation = verify_generation + 1, verify_token_hash = p_token_hash,
           verify_expires_at = p_now + interval '30 minutes', verify_failures = 0
     WHERE tenant_id = v_tenant AND request_id = p_request AND state = 'VERIFYING'
       AND email IS NOT NULL
    RETURNING verify_expires_at INTO v_expires;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    RETURN v_expires;
END $$
"""

CHECK = r"""
CREATE FUNCTION execbound.signup_verify_check(p_request uuid, p_token_hash text, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_request execbound.signup_requests%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_request IS NULL OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_request FROM execbound.signup_requests r
     WHERE r.tenant_id = v_tenant AND r.request_id = p_request FOR UPDATE;
    IF NOT FOUND OR v_request.email IS NULL OR v_request.verify_token_hash IS NULL
       OR v_request.state NOT IN ('VERIFYING', 'PROVISIONED') OR v_request.verify_failures >= 5
    THEN
        RETURN NULL;
    END IF;
    IF v_request.verify_token_hash <> p_token_hash THEN
        UPDATE execbound.signup_requests SET verify_failures = verify_failures + 1
         WHERE tenant_id = v_tenant AND request_id = p_request;
        RETURN NULL;
    END IF;
    RETURN jsonb_build_object(
        'state', CASE WHEN v_request.state = 'VERIFYING' AND v_request.verify_expires_at <= p_now
                      THEN 'EXPIRED' ELSE v_request.state END,
        'email', v_request.email,
        'expires_at', v_request.verify_expires_at,
        'tenant_id', v_request.provisioned_tenant_id);
END $$
"""

PROVISION = r"""
CREATE FUNCTION execbound.community_provision(
    p_request uuid, p_token_hash text, p_tenant uuid, p_principal uuid, p_account uuid,
    p_name text, p_slug text, p_password jsonb, p_capacity integer, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_operator uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_signed_in uuid := nullif(current_setting('execbound.account_id', true), '')::uuid;
    v_request execbound.signup_requests%ROWTYPE;
    v_account execbound.user_accounts%ROWTYPE;
    v_account_id uuid;
    v_member record;
    v_space uuid := gen_random_uuid();
    v_version bigint;
BEGIN
    IF v_operator IS NULL OR p_request IS NULL OR p_tenant IS NULL OR p_principal IS NULL
       OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
       OR p_capacity IS NULL OR p_capacity < 1 THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_name IS NULL OR p_name <> btrim(p_name) OR length(p_name) NOT BETWEEN 1 AND 120 THEN
        RAISE EXCEPTION 'INVALID_NAME';
    END IF;
    IF p_slug IS NULL OR p_slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$'
       OR length(p_slug) NOT BETWEEN 3 AND 63 THEN
        RAISE EXCEPTION 'INVALID_SLUG';
    END IF;
    -- Exactly one proof of the person: a new password for a new account, or an account the
    -- caller has already authenticated in this transaction. Never both, never neither.
    IF (p_password IS NULL) = (v_signed_in IS NULL)
       OR (p_password IS NOT NULL AND p_account IS NULL) THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;

    -- 1. The request and admission capacity. The caller holds the operator tenant's fence,
    --    which serializes this count against every completion and every submission.
    SELECT * INTO v_request FROM execbound.signup_requests r
     WHERE r.tenant_id = v_operator AND r.request_id = p_request FOR UPDATE;
    IF NOT FOUND OR v_request.email IS NULL OR v_request.verify_token_hash IS NULL
       OR v_request.verify_failures >= 5 THEN
        RETURN NULL;
    END IF;
    IF v_request.verify_token_hash <> p_token_hash THEN
        UPDATE execbound.signup_requests SET verify_failures = verify_failures + 1
         WHERE tenant_id = v_operator AND request_id = p_request;
        RETURN NULL;
    END IF;
    IF v_request.state = 'PROVISIONED' THEN
        RETURN jsonb_build_object('outcome', 'ALREADY',
                                  'tenant_id', v_request.provisioned_tenant_id);
    END IF;
    IF v_request.state <> 'VERIFYING' OR v_request.verify_expires_at <= p_now THEN
        RAISE EXCEPTION 'INVALID_TOKEN';
    END IF;
    IF (SELECT count(*) FROM execbound.signup_requests r
         WHERE r.tenant_id = v_operator AND r.state = 'PROVISIONED') >= p_capacity THEN
        -- Verification never reserved a workspace. Back to the queue, with its note.
        UPDATE execbound.signup_requests
           SET state = 'QUEUED', verify_token_hash = NULL, verify_expires_at = NULL
         WHERE tenant_id = v_operator AND request_id = p_request;
        INSERT INTO execbound.signup_messages
            (tenant_id, message_id, request_id, message_class, created_at, next_attempt_at)
        VALUES (v_operator, gen_random_uuid(), p_request, 'waitlist', p_now, p_now)
        ON CONFLICT (tenant_id, request_id, message_class) DO NOTHING;
        RETURN jsonb_build_object('outcome', 'CAPACITY');
    END IF;

    -- 2. The account, locked before any tenant row is written.
    IF p_password IS NOT NULL THEN
        -- A new account only for an address nobody signs in with yet: not one an account
        -- holds, and not one an active person set up before accounts existed holds (their
        -- first password sign-in adopts theirs). The marker is what the `sign_in_email`
        -- policies read, so both lookups see every tenant under forced row-level security.
        PERFORM set_config('execbound.sign_in_email', v_request.email, true);
        IF EXISTS (SELECT 1 FROM execbound.user_accounts WHERE email = v_request.email)
           OR EXISTS (SELECT 1 FROM execbound.principals p
                       WHERE p.email = v_request.email AND p.active
                         AND p.kind IN ('ADMIN', 'HUMAN_APPROVER')) THEN
            RAISE EXCEPTION 'ACCOUNT_EXISTS';
        END IF;
        PERFORM set_config('execbound.sign_in_email', '', true);
        PERFORM set_config('execbound.account_id', p_account::text, true);
        BEGIN
            INSERT INTO execbound.user_accounts(account_id, email, email_verified_at)
            VALUES (p_account, v_request.email, p_now);
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
        IF NOT FOUND OR NOT v_account.active OR v_account.email <> v_request.email THEN
            RAISE EXCEPTION 'ACCOUNT_MISMATCH';
        END IF;
        v_account_id := v_signed_in;
        IF EXISTS (SELECT 1 FROM execbound.community_allocations
                    WHERE account_id = v_account_id AND state = 'consumed') THEN
            RAISE EXCEPTION 'ALLOCATION_USED';
        END IF;
        -- An ambiguous historic claim involving this account's principals waits for the
        -- operator's resolution rather than being answered with a second workspace.
        FOR v_member IN
            SELECT m.tenant_id, m.principal_id FROM execbound.workspace_memberships m
             WHERE m.account_id = v_account_id ORDER BY m.tenant_id
        LOOP
            PERFORM set_config('execbound.tenant_id', v_member.tenant_id::text, true);
            IF EXISTS (SELECT 1 FROM execbound.community_allocations a
                        WHERE a.tenant_id = v_member.tenant_id AND a.state = 'unresolved'
                          AND (a.claimant_principal_id IS NULL
                               OR a.claimant_principal_id = v_member.principal_id)) THEN
                RAISE EXCEPTION 'ALLOCATION_UNRESOLVED';
            END IF;
        END LOOP;
        -- The link proved the mailbox, so a legacy address becomes a verified one.
        UPDATE execbound.user_accounts
           SET email_verified_at = coalesce(email_verified_at, p_now)
         WHERE account_id = v_account_id;
    END IF;
    SELECT version INTO v_version FROM execbound.user_accounts WHERE account_id = v_account_id;

    -- 3. The workspace: all of it or none of it.
    PERFORM set_config('execbound.tenant_id', p_tenant::text, true);
    BEGIN
        INSERT INTO execbound.tenants(tenant_id, name, active, plan, slug, provisioned_at)
        VALUES (p_tenant, p_name, true, 'free', p_slug, p_now);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'SLUG_TAKEN';
    END;
    INSERT INTO execbound.principals(tenant_id, principal_id, kind)
    VALUES (p_tenant, p_principal, 'ADMIN');
    BEGIN
        UPDATE execbound.principals SET email = v_request.email
         WHERE tenant_id = p_tenant AND principal_id = p_principal;
    EXCEPTION WHEN unique_violation THEN
        -- Another workspace's principal holds this address; the account alone carries it.
        -- For a new account that holder committed after the check above, so it is checked
        -- again: an active person is the same refusal, and an inactive one is not.
        IF p_password IS NOT NULL THEN
            PERFORM set_config('execbound.sign_in_email', v_request.email, true);
            IF EXISTS (SELECT 1 FROM execbound.principals p
                        WHERE p.email = v_request.email AND p.active
                          AND p.kind IN ('ADMIN', 'HUMAN_APPROVER')) THEN
                RAISE EXCEPTION 'ACCOUNT_EXISTS';
            END IF;
            PERFORM set_config('execbound.sign_in_email', '', true);
        END IF;
    END;
    INSERT INTO execbound.spaces(tenant_id, space_id, name, detail, created_at, created_by)
    VALUES (p_tenant, v_space, 'Default', NULL, p_now, p_principal);
    INSERT INTO execbound.workspace_memberships(account_id, tenant_id, principal_id)
    VALUES (v_account_id, p_tenant, p_principal);
    BEGIN
        INSERT INTO execbound.community_allocations
            (tenant_id, claimant_principal_id, account_id, state, retained_at)
        VALUES (p_tenant, p_principal, v_account_id, 'consumed', p_now);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'ALLOCATION_USED';
    END;

    -- 4. The request records its one outcome, so a retry finds it rather than making another.
    PERFORM set_config('execbound.tenant_id', v_operator::text, true);
    UPDATE execbound.signup_requests
       SET state = 'PROVISIONED', provisioned_tenant_id = p_tenant,
           provisioned_account_id = v_account_id, provisioned_at = p_now,
           purge_after = p_now + interval '90 days'
     WHERE tenant_id = v_operator AND request_id = p_request;
    RETURN jsonb_build_object(
        'outcome', 'PROVISIONED', 'tenant_id', p_tenant, 'principal_id', p_principal,
        'account_id', v_account_id, 'space_id', v_space,
        'consent_version', v_request.consent_version, 'account_version', v_version);
END $$
"""


def live_function(name: str) -> str:
    """The installed definition, including every later access-control patch."""
    return str(
        op.get_bind()
        .execute(
            text("""SELECT pg_get_functiondef(p.oid)
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'execbound' AND p.proname = :name"""),
            {"name": name},
        )
        .scalar_one()
    )


def replace_once(body: str, old: str, new: str, *, reverse: bool = False) -> str:
    if reverse:
        old, new = new, old
    assert body.count(old) == 1, "Unexpected predecessor function definition"
    return body.replace(old, new, 1)


PATCHES = {
    # A live workspace counts against its domain's cap however it came to exist.
    "signup_request": (
        "AND r.state IN ('INVITED', 'CLAIMED')",
        "AND r.state IN ('INVITED', 'CLAIMED', 'VERIFYING', 'PROVISIONED')",
    ),
    # An unfinished verification lapses like an unredeemed invitation, and its link dies.
    "signup_mark": (
        "OR (p_state = 'EXPIRED' AND state IN ('QUEUED', 'INVITED', 'CLAIMED')));",
        "OR (p_state = 'EXPIRED' AND state IN ('QUEUED', 'INVITED', 'CLAIMED', 'VERIFYING')));",
    ),
    # Silence is measured from provisioning where there is no claimed slot.
    "agents_sleep": (
        "SELECT s.claimed_at INTO v_claimed FROM execbound.onboarding_slots s\n"
        "     WHERE s.tenant_id = v_tenant;",
        "SELECT coalesce(s.claimed_at, t.provisioned_at) INTO v_claimed\n"
        "      FROM execbound.tenants t\n"
        "      LEFT JOIN execbound.onboarding_slots s ON s.tenant_id = t.tenant_id\n"
        "     WHERE t.tenant_id = v_tenant;",
    ),
}
MARK_CLEARS = (
    "purge_after = p_purge_after\n     WHERE tenant_id = v_tenant AND request_id = p_request",
    "purge_after = p_purge_after,\n"
    "           verify_token_hash = CASE WHEN p_state = 'EXPIRED' THEN NULL\n"
    "                                    ELSE verify_token_hash END\n"
    "     WHERE tenant_id = v_tenant AND request_id = p_request",
)
# CS04: a link that expired without being provisioned must not hold the address cooldown --
# nobody has a workspace, and thirty days (well, `p_cooldown_days`) of silence for asking
# again is a dead end the design does not want. A row that completed (`provisioned_at` set)
# or that was never sent a link at all (`verifying_at` still NULL, refused/still-QUEUED/etc.)
# keeps counting: this excludes only a verification that was actually offered and expired.
REQUEST_COOLDOWN_EXCLUDES_EXPIRED_VERIFICATION = (
    "WHERE r.tenant_id = v_tenant AND r.email = p_email AND r.state <> 'REFUSED'\n"
    "           AND r.requested_at > p_now - make_interval(days => p_cooldown_days)",
    "WHERE r.tenant_id = v_tenant AND r.email = p_email AND r.state <> 'REFUSED'\n"
    "           AND NOT (r.state = 'EXPIRED' AND r.verifying_at IS NOT NULL\n"
    "                    AND r.provisioned_at IS NULL)\n"
    "           AND r.requested_at > p_now - make_interval(days => p_cooldown_days)",
)


def patch_functions(*, reverse: bool = False) -> None:
    for name, (old, new) in PATCHES.items():
        body = replace_once(live_function(name), old, new, reverse=reverse)
        if name == "signup_mark":
            body = replace_once(body, *MARK_CLEARS, reverse=reverse)
        if name == "signup_request":
            body = replace_once(
                body, *REQUEST_COOLDOWN_EXCLUDES_EXPIRED_VERIFICATION, reverse=reverse
            )
        op.execute(body)


def upgrade() -> None:
    op.execute(f"""
        ALTER TABLE execbound.signup_requests
            DROP CONSTRAINT signup_requests_state_check,
            ADD CONSTRAINT signup_requests_state_check CHECK (state IN {STATES}),
            ADD COLUMN verify_generation integer NOT NULL DEFAULT 0
                CHECK (verify_generation >= 0),
            ADD COLUMN verify_token_hash text
                CHECK (verify_token_hash IS NULL OR verify_token_hash ~ '^[0-9a-f]{{64}}$'),
            ADD COLUMN verify_expires_at timestamptz,
            ADD COLUMN verify_failures integer NOT NULL DEFAULT 0
                CHECK (verify_failures BETWEEN 0 AND 5),
            ADD COLUMN verify_sends integer NOT NULL DEFAULT 0
                CHECK (verify_sends BETWEEN 0 AND 5),
            ADD COLUMN verifying_at timestamptz,
            ADD COLUMN provisioned_tenant_id uuid,
            ADD COLUMN provisioned_account_id uuid,
            ADD COLUMN provisioned_at timestamptz,
            ADD CONSTRAINT signup_requests_provisioned CHECK (
                (provisioned_tenant_id IS NULL) = (provisioned_at IS NULL)
                AND (provisioned_tenant_id IS NULL) = (provisioned_account_id IS NULL)
                AND (state <> 'PROVISIONED' OR provisioned_tenant_id IS NOT NULL)
                AND (state <> 'VERIFYING' OR verifying_at IS NOT NULL))
    """)
    op.execute(
        "CREATE UNIQUE INDEX signup_requests_provisioned_tenant "
        "ON execbound.signup_requests (provisioned_tenant_id) "
        "WHERE provisioned_tenant_id IS NOT NULL"
    )
    op.execute(f"""
        ALTER TABLE execbound.signup_messages
            DROP CONSTRAINT signup_messages_message_class_check,
            ADD CONSTRAINT signup_messages_message_class_check
                CHECK (message_class IN {CLASSES})
    """)
    op.execute("""
        ALTER TABLE execbound.tenants
            ADD COLUMN slug text CHECK (slug IS NULL OR (
                slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND length(slug) BETWEEN 3 AND 63)),
            ADD COLUMN provisioned_at timestamptz
    """)
    op.execute(
        "CREATE UNIQUE INDEX tenants_slug ON execbound.tenants (slug) WHERE slug IS NOT NULL"
    )
    op.execute("DROP INDEX execbound.tenants_name_lower")
    for body in (QUEUE, REKEY, CHECK, PROVISION):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")
    patch_functions()


def downgrade() -> None:
    for table in ("signup_requests", "tenants"):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    populated = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.signup_requests "
                "  WHERE state IN ('VERIFYING', 'PROVISIONED') "
                "     OR provisioned_tenant_id IS NOT NULL) "
                "OR EXISTS (SELECT 1 FROM execbound.tenants "
                "  WHERE slug IS NOT NULL OR provisioned_at IS NOT NULL) "
                "OR EXISTS (SELECT lower(name) FROM execbound.tenants "
                "  GROUP BY lower(name) HAVING count(*) > 1)"
            )
        )
        .scalar_one()
    )
    for table in ("signup_requests", "tenants"):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    if populated:
        raise RuntimeError(
            "Community signup data requires a verified full restore; lossy downgrade refused"
        )
    patch_functions(reverse=True)
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("CREATE UNIQUE INDEX tenants_name_lower ON execbound.tenants (lower(name))")
    op.execute("DROP INDEX execbound.tenants_slug")
    op.execute("ALTER TABLE execbound.tenants DROP COLUMN slug, DROP COLUMN provisioned_at")
    op.execute("ALTER TABLE execbound.signup_messages NO FORCE ROW LEVEL SECURITY")
    op.execute("DELETE FROM execbound.signup_messages WHERE message_class = 'verification'")
    op.execute("ALTER TABLE execbound.signup_messages FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        ALTER TABLE execbound.signup_messages
            DROP CONSTRAINT signup_messages_message_class_check,
            ADD CONSTRAINT signup_messages_message_class_check
                CHECK (message_class IN {OLD_CLASSES})
    """)
    op.execute("DROP INDEX execbound.signup_requests_provisioned_tenant")
    op.execute(f"""
        ALTER TABLE execbound.signup_requests
            DROP CONSTRAINT signup_requests_provisioned,
            DROP COLUMN verify_generation, DROP COLUMN verify_token_hash,
            DROP COLUMN verify_expires_at, DROP COLUMN verify_failures,
            DROP COLUMN verify_sends, DROP COLUMN verifying_at,
            DROP COLUMN provisioned_tenant_id, DROP COLUMN provisioned_account_id,
            DROP COLUMN provisioned_at,
            DROP CONSTRAINT signup_requests_state_check,
            ADD CONSTRAINT signup_requests_state_check CHECK (state IN {OLD_STATES})
    """)
