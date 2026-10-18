"""Open sandbox signups: requests, the message outbox and the sandbox lifecycle.

A signup request is a stranger's asking for a sandbox. It lives in the operator tenant, because
every row belongs to a tenant and a request precedes the prospect's. A message is one queued,
leased, retried delivery to the address that asked: the invitation whose code is minted inside the
send, the waitlist note when the pool is empty, and the notice three days before a sandbox ends.

The runtime role gains EXECUTE on seven fenced functions with no actor, SELECT on both new tables,
and UPDATE on exactly the seven delivery columns of the outbox, which a leased queue has to move
for itself. It gains no write on `signup_requests`, `onboarding_slots`, `onboarding_invitations` or
`tenants`: everything consequential happens inside a function the schema owner owns.

`onboarding_slots` gains the lifecycle. `expires_at` is kept by a trigger at `claimed_at` plus
fourteen days rather than written by `onboarding_claim`, for two reasons: the claim of `0028` has
already run over the sandboxes that exist and rewriting its body under them buys nothing a trigger
does not, and the invariant then holds for every row however it was written, including the slot
`sandbox-adopt` records for a tenant that was never seeded. `extended_until`, `deactivated_at` and
`converted_at` are what move or end it, and every sandbox already claimed when this migration runs
is stamped converted, so nothing that is already running acquires a two-week fuse retroactively.
"""

from alembic import op
from sqlalchemy import text

revision = "0039_signups"
down_revision = "0038_assistant_turns"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
DIGEST = "^[0-9a-f]{64}$"
STATES = "('QUEUED', 'INVITED', 'CLAIMED', 'EXPIRED', 'REFUSED')"
CLASSES = "('invitation', 'waitlist', 'lifecycle')"
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
    "onboarding_invite(text, text, timestamptz)",
    "onboarding_invitation_rekey(uuid, text)",
    "sandbox_expire(text, timestamptz)",
    "sandbox_notice(timestamptz)",
    "signup_request(uuid, text, text, boolean, text, timestamptz, text, integer, integer, "
    "integer, integer, integer)",
    "signup_allocate(uuid, uuid, uuid, uuid, text, timestamptz)",
    "signup_mark(uuid, text, timestamptz, timestamptz)",
)

# One invitation for one free slot, with no actor: the authority is the operator's configuration,
# exactly as the claim's authority is the code. The initial hash is a random digest the caller
# throws away, so the invitation exists and can be pointed at but nothing can redeem it until the
# send mints a real code. An invitation that has expired without being redeemed is revoked here,
# which is what lets the partial unique index admit the next one.
INVITE = r"""
CREATE FUNCTION execbound.onboarding_invite(
    p_note text, p_token_hash text, p_expires_at timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_invitation uuid := gen_random_uuid();
    v_live execbound.onboarding_invitations%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_note IS NULL OR length(btrim(p_note)) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'INVALID_NOTE';
    END IF;
    IF p_expires_at IS NULL OR p_expires_at <= now()
       OR p_expires_at - now() > interval '30 days' THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND NOT t.active
    ) OR NOT EXISTS (
        SELECT 1 FROM execbound.onboarding_slots s
        WHERE s.tenant_id = v_tenant AND s.claimed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    SELECT * INTO v_live FROM execbound.onboarding_invitations i
     WHERE i.tenant_id = v_tenant AND i.redeemed_at IS NULL AND i.revoked_at IS NULL
     FOR UPDATE;
    IF FOUND THEN
        IF v_live.expires_at > now() THEN
            RAISE EXCEPTION 'INVITATION_LIVE';
        END IF;
        UPDATE execbound.onboarding_invitations SET revoked_at = now()
         WHERE tenant_id = v_tenant AND invitation_id = v_live.invitation_id;
    END IF;
    INSERT INTO execbound.onboarding_invitations
        (tenant_id, invitation_id, token_hash, note, issued_at, expires_at)
    VALUES (v_tenant, v_invitation, p_token_hash, btrim(p_note), now(), p_expires_at);
    RETURN v_invitation;
END $$
"""

# The send mints the code. Every attempt replaces the hash, so exactly one delivered code is ever
# valid and a code from an attempt whose delivery was uncertain never works.
REKEY = r"""
CREATE FUNCTION execbound.onboarding_invitation_rekey(p_invitation uuid, p_token_hash text)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_invitation execbound.onboarding_invitations%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_invitation IS NULL OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    SELECT * INTO v_invitation FROM execbound.onboarding_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND OR v_invitation.revoked_at IS NOT NULL
       OR v_invitation.redeemed_at IS NOT NULL OR v_invitation.expires_at <= now() THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    UPDATE execbound.onboarding_invitations SET token_hash = p_token_hash, failure_count = 0
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    RETURN v_invitation.expires_at;
END $$
"""

# A sandbox reaching its end. The tenant goes inactive with a reason, which is what every check
# downstream already reads: sessions, credentials and agent requests fail at their next check as
# they do for any inactive tenant. The caller appends `tenant.expired` under the same fence, and
# the actor returned here is the sandbox's own first administrator, so the event belongs to the
# chain of the tenant it is about. A converted sandbox has no end and is refused.
EXPIRE = r"""
CREATE FUNCTION execbound.sandbox_expire(p_reason text, p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_slot execbound.onboarding_slots%ROWTYPE;
    v_actor uuid;
BEGIN
    IF v_tenant IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z][a-z0-9_]{0,39}$' THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_slot FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant FOR UPDATE;
    IF NOT FOUND OR v_slot.claimed_at IS NULL OR v_slot.converted_at IS NOT NULL
       OR v_slot.deactivated_at IS NOT NULL
       OR coalesce(v_slot.extended_until, v_slot.expires_at) > p_now THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    SELECT p.principal_id INTO v_actor FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.kind = 'ADMIN' AND p.active
     ORDER BY p.principal_id LIMIT 1;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    UPDATE execbound.tenants SET active = false WHERE tenant_id = v_tenant;
    UPDATE execbound.onboarding_slots SET deactivated_at = p_now WHERE tenant_id = v_tenant;
    RETURN v_actor;
END $$
"""

# The notice three days before the end. Stamping the slot is what makes "once" true: the
# request's own `notice_sent_at` and the outbox's one-message-per-class index say it too, and
# all three have to be wrong before a person is told twice that their sandbox is ending.
NOTICE = r"""
CREATE FUNCTION execbound.sandbox_notice(p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_slot execbound.onboarding_slots%ROWTYPE;
    v_end timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_slot FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant FOR UPDATE;
    IF NOT FOUND OR v_slot.claimed_at IS NULL OR v_slot.converted_at IS NOT NULL
       OR v_slot.deactivated_at IS NOT NULL OR v_slot.notice_at IS NOT NULL THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    v_end := coalesce(v_slot.extended_until, v_slot.expires_at);
    IF v_end IS NULL OR v_end <= p_now OR v_end - p_now > interval '3 days' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    UPDATE execbound.onboarding_slots SET notice_at = p_now WHERE tenant_id = v_tenant;
    RETURN v_end;
END $$
"""


# One request, with every cap evaluated against the snapshot the row is written in, so a second
# request racing the last unit of a cap loses on the count it reads rather than on a check the
# application made a moment earlier. A refusal is a row too: the funnel counts it, and the page
# above says the same thing it says for a success.
#
# `p_refusal` is a code the caller already reached (a filled honeypot, a disposable domain): the
# database is not asked to hold a list of domains, only to record what was decided about one.
# A refused row never starts the address cooldown, so a mistyped honeypot is not a month's
# lockout; the hourly and daily caps are what bound a flood of refusals.
REQUEST = r"""
CREATE FUNCTION execbound.signup_request(
    p_request uuid, p_email text, p_domain text, p_free_mail boolean, p_consent text,
    p_now timestamptz, p_refusal text, p_per_hour integer, p_per_day integer,
    p_per_domain integer, p_free_mail_daily integer, p_cooldown_days integer)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_code text := p_refusal;
    v_purge timestamptz;
BEGIN
    IF v_tenant IS NULL OR p_request IS NULL OR p_email IS NULL OR p_domain IS NULL
       OR p_consent IS NULL OR p_free_mail IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_email <> lower(p_email) OR length(p_email) NOT BETWEEN 3 AND 254
       OR length(p_domain) NOT BETWEEN 1 AND 253
       OR length(p_consent) NOT BETWEEN 1 AND 40 THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_per_hour IS NULL OR p_per_day IS NULL OR p_per_domain IS NULL
       OR p_free_mail_daily IS NULL OR p_cooldown_days IS NULL
       OR least(p_per_hour, p_per_day, p_per_domain, p_free_mail_daily, p_cooldown_days) < 1 THEN
        RAISE EXCEPTION 'INVALID_LIMIT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF v_code IS NULL AND (
        SELECT count(*) FROM execbound.signup_requests r
         WHERE r.tenant_id = v_tenant AND r.requested_at > p_now - interval '1 hour'
    ) >= p_per_hour THEN
        v_code := 'GLOBAL_HOURLY_CAP';
    END IF;
    IF v_code IS NULL AND (
        SELECT count(*) FROM execbound.signup_requests r
         WHERE r.tenant_id = v_tenant AND r.requested_at > p_now - interval '1 day'
    ) >= p_per_day THEN
        v_code := 'GLOBAL_DAILY_CAP';
    END IF;
    IF v_code IS NULL AND EXISTS (
        SELECT 1 FROM execbound.signup_requests r
         WHERE r.tenant_id = v_tenant AND r.email = p_email AND r.state <> 'REFUSED'
           AND r.requested_at > p_now - make_interval(days => p_cooldown_days)
    ) THEN
        v_code := 'ADDRESS_COOLDOWN';
    END IF;
    IF v_code IS NULL AND p_free_mail AND (
        SELECT count(*) FROM execbound.signup_requests r
         WHERE r.tenant_id = v_tenant AND r.free_mail AND r.state <> 'REFUSED'
           AND r.requested_at > p_now - interval '1 day'
    ) >= p_free_mail_daily THEN
        v_code := 'FREE_MAIL_DAILY_CAP';
    END IF;
    IF v_code IS NULL AND NOT p_free_mail AND (
        SELECT count(*) FROM execbound.signup_requests r
         WHERE r.tenant_id = v_tenant AND r.domain = p_domain
           AND r.state IN ('INVITED', 'CLAIMED')
    ) >= p_per_domain THEN
        v_code := 'DOMAIN_CAP';
    END IF;
    v_purge := CASE WHEN v_code IS NULL THEN NULL ELSE p_now + interval '30 days' END;
    INSERT INTO execbound.signup_requests
        (tenant_id, request_id, email, domain, free_mail, consent_version, requested_at,
         state, refusal_code, purge_after)
    VALUES (v_tenant, p_request, p_email, p_domain, p_free_mail, p_consent, p_now,
            CASE WHEN v_code IS NULL THEN 'QUEUED' ELSE 'REFUSED' END, v_code, v_purge);
    RETURN coalesce(v_code, 'QUEUED');
END $$
"""

# Allocation, the waitlist note and the lifecycle notice are one write each: the request moves and
# the message that says so is queued in the same statement, so a queue can never hold a message
# for a request that does not say it was sent one.
ALLOCATE = r"""
CREATE FUNCTION execbound.signup_allocate(
    p_request uuid, p_slot_tenant uuid, p_invitation uuid, p_message uuid, p_class text,
    p_now timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_request execbound.signup_requests%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_request IS NULL OR p_message IS NULL
       OR p_class NOT IN ('invitation', 'waitlist', 'lifecycle') THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF (p_class = 'invitation') <> (p_slot_tenant IS NOT NULL AND p_invitation IS NOT NULL) THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    SELECT * INTO v_request FROM execbound.signup_requests r
     WHERE r.tenant_id = v_tenant AND r.request_id = p_request FOR UPDATE;
    IF NOT FOUND OR v_request.email IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_class = 'invitation' THEN
        IF v_request.state <> 'QUEUED' THEN
            RAISE EXCEPTION 'INVALID_STATE';
        END IF;
        UPDATE execbound.signup_requests
           SET state = 'INVITED', slot_tenant_id = p_slot_tenant, invitation_id = p_invitation,
               invited_at = p_now
         WHERE tenant_id = v_tenant AND request_id = p_request;
    ELSIF p_class = 'waitlist' THEN
        IF v_request.state <> 'QUEUED' THEN
            RAISE EXCEPTION 'INVALID_STATE';
        END IF;
    ELSE
        IF v_request.state NOT IN ('INVITED', 'CLAIMED') OR v_request.notice_sent_at IS NOT NULL
        THEN
            RAISE EXCEPTION 'INVALID_STATE';
        END IF;
        UPDATE execbound.signup_requests SET notice_sent_at = p_now
         WHERE tenant_id = v_tenant AND request_id = p_request;
    END IF;
    -- One message of a class per request, and a second attempt to queue one is a no-op
    -- rather than an error: the waitlist sweep runs every quarter of an hour over requests
    -- that are still waiting, and each of those already holds its note.
    INSERT INTO execbound.signup_messages
        (tenant_id, message_id, request_id, message_class, slot_tenant_id, invitation_id,
         created_at, next_attempt_at)
    VALUES (v_tenant, p_message, p_request, p_class, p_slot_tenant, p_invitation, p_now, p_now)
    ON CONFLICT (tenant_id, request_id, message_class) DO NOTHING;
    RETURN p_class;
END $$
"""

# The rest of a request's life: claimed, expired with its sandbox, and the retention pass that
# drops the address and keeps the domain and the timestamps for the funnel. A NULL request with
# state PURGE is the bulk pass, which is the one operation that is about no single request.
MARK = r"""
CREATE FUNCTION execbound.signup_mark(
    p_request uuid, p_state text, p_at timestamptz, p_purge_after timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_count integer;
BEGIN
    IF v_tenant IS NULL OR p_state IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_at IS NULL OR abs(extract(epoch FROM (p_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_request IS NULL THEN
        IF p_state <> 'PURGE' THEN
            RAISE EXCEPTION 'INVALID_STATE';
        END IF;
        UPDATE execbound.signup_requests SET email = NULL, purge_after = NULL
         WHERE tenant_id = v_tenant AND email IS NOT NULL
           AND purge_after IS NOT NULL AND purge_after <= p_at;
        GET DIAGNOSTICS v_count = ROW_COUNT;
        RETURN v_count;
    END IF;
    IF p_state NOT IN ('CLAIMED', 'EXPIRED') THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    UPDATE execbound.signup_requests
       SET state = p_state,
           claimed_at = CASE WHEN p_state = 'CLAIMED' THEN p_at ELSE claimed_at END,
           purge_after = p_purge_after
     WHERE tenant_id = v_tenant AND request_id = p_request
       AND ((p_state = 'CLAIMED' AND state = 'INVITED')
            OR (p_state = 'EXPIRED' AND state IN ('QUEUED', 'INVITED', 'CLAIMED')));
    GET DIAGNOSTICS v_count = ROW_COUNT;
    IF v_count = 0 THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    RETURN v_count;
END $$
"""


# The one invariant that is not a function's to keep, because it is true of the row rather than of
# an operation: a claimed slot ends fourteen days after it was claimed unless something moved it.
# Trigger functions are not callable by the runtime and `check_runtime` says so.
EXPIRES_TRIGGER = r"""
CREATE FUNCTION execbound.onboarding_slot_expiry()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    NEW.expires_at := CASE
        WHEN NEW.claimed_at IS NULL THEN NULL
        ELSE NEW.claimed_at + interval '14 days' END;
    RETURN NEW;
END $$
"""


def _lift_rls(tables: tuple[str, ...]) -> None:
    op.execute(
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in tables) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")


def _restore_rls(tables: tuple[str, ...]) -> None:
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def _protect(table: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.{table}
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    for role in ("PUBLIC", "anon", "authenticated", "service_role", "execbound_app"):
        if role != "PUBLIC" and not _role_exists(role):
            continue
        op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE execbound.signup_requests (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            request_id uuid NOT NULL,
            email text CHECK (email IS NULL OR (length(email) BETWEEN 3 AND 254
                              AND email = lower(email))),
            domain text NOT NULL CHECK (length(domain) BETWEEN 1 AND 253
                                        AND domain = lower(domain)),
            free_mail boolean NOT NULL DEFAULT false,
            consent_version text NOT NULL CHECK (length(consent_version) BETWEEN 1 AND 40),
            requested_at timestamptz NOT NULL,
            state text NOT NULL CHECK (state IN {STATES}),
            refusal_code text CHECK (refusal_code IS NULL
                                     OR refusal_code ~ '^[A-Z][A-Z0-9_]{{0,39}}$'),
            slot_tenant_id uuid,
            invitation_id uuid,
            invited_at timestamptz,
            claimed_at timestamptz,
            notice_sent_at timestamptz,
            purge_after timestamptz,
            PRIMARY KEY (tenant_id, request_id),
            CONSTRAINT signup_requests_refused
                CHECK ((state = 'REFUSED') = (refusal_code IS NOT NULL)),
            CONSTRAINT signup_requests_invited
                CHECK ((slot_tenant_id IS NOT NULL) = (invitation_id IS NOT NULL)
                       AND (slot_tenant_id IS NOT NULL) = (invited_at IS NOT NULL))
        )
    """)
    _protect("signup_requests")
    # The waitlist is walked in arrival order, and the cooldown is a lookup by address.
    op.execute(
        "CREATE INDEX signup_requests_queued ON execbound.signup_requests "
        "(tenant_id, requested_at, request_id) WHERE state = 'QUEUED'"
    )
    op.execute(
        "CREATE INDEX signup_requests_address ON execbound.signup_requests "
        "(tenant_id, email, requested_at) WHERE email IS NOT NULL"
    )
    # The operator's ADMIN reads the list and the report; nothing writes without a function.
    op.execute("GRANT SELECT ON execbound.signup_requests TO execbound_app")
    op.execute(f"""
        CREATE TABLE execbound.signup_messages (
            tenant_id uuid NOT NULL,
            message_id uuid NOT NULL,
            request_id uuid NOT NULL,
            message_class text NOT NULL CHECK (message_class IN {CLASSES}),
            slot_tenant_id uuid,
            invitation_id uuid,
            created_at timestamptz NOT NULL,
            state text NOT NULL DEFAULT 'PENDING'
                CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED')),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
            next_attempt_at timestamptz NOT NULL,
            lease_until timestamptz,
            lease_token uuid,
            delivered_at timestamptz,
            last_error text CHECK (last_error IS NULL
                                   OR last_error ~ '^[A-Z][A-Z0-9_]{{0,63}}$'),
            PRIMARY KEY (tenant_id, message_id),
            FOREIGN KEY (tenant_id, request_id)
                REFERENCES execbound.signup_requests (tenant_id, request_id),
            UNIQUE (tenant_id, request_id, message_class)
        )
    """)
    _protect("signup_messages")
    op.execute(
        "CREATE INDEX signup_messages_pending ON execbound.signup_messages "
        "(tenant_id, next_attempt_at, message_id) WHERE state IN ('PENDING', 'IN_FLIGHT')"
    )
    op.execute("GRANT SELECT ON execbound.signup_messages TO execbound_app")
    # The one table the runtime moves for itself, and only the lease and the outcome: a queue
    # that cannot record its own attempt would need a definer call per retry per message.
    op.execute(
        "GRANT UPDATE (" + ", ".join(DELIVERY) + ") ON execbound.signup_messages TO execbound_app"
    )
    # The lifecycle. A generated column cannot hold this: adding an interval to a timestamptz is
    # stable rather than immutable, because a day is not always 24 hours. A trigger keeps the
    # same invariant, for every writer, without `0028_onboarding`'s claim being rewritten under
    # the sandboxes it has already run for.
    op.execute("""
        ALTER TABLE execbound.onboarding_slots
            ADD COLUMN expires_at timestamptz,
            ADD COLUMN notice_at timestamptz,
            ADD COLUMN extended_until timestamptz,
            ADD COLUMN deactivated_at timestamptz,
            ADD COLUMN converted_at timestamptz,
            ADD CONSTRAINT onboarding_slots_lifecycle CHECK (
                (notice_at IS NULL AND extended_until IS NULL AND deactivated_at IS NULL
                 AND converted_at IS NULL AND expires_at IS NULL) OR claimed_at IS NOT NULL)
    """)
    op.execute(EXPIRES_TRIGGER)
    op.execute(
        "CREATE TRIGGER onboarding_slot_expiry BEFORE INSERT OR UPDATE "
        "ON execbound.onboarding_slots FOR EACH ROW "
        "EXECUTE FUNCTION execbound.onboarding_slot_expiry()"
    )
    # Every sandbox that is already running keeps running. The pilot tenant `sandbox-adopt`
    # recorded and the showcase slot are both claimed slots; giving them a fourteen-day fuse
    # because a migration ran would deactivate the pilot and take the public board down with it.
    # The lifecycle applies to what is claimed from here on.
    _lift_rls(("onboarding_slots",))
    op.execute(
        "UPDATE execbound.onboarding_slots SET converted_at = now() WHERE claimed_at IS NOT NULL"
    )
    _restore_rls(("onboarding_slots",))
    for body in (INVITE, REKEY, EXPIRE, NOTICE, REQUEST, ALLOCATE, MARK):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if _role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    # A claimed sandbox keeps its slot row and its tenant; only the lifecycle and the funnel
    # go, and neither holds anything the audit chain does not.
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP TRIGGER onboarding_slot_expiry ON execbound.onboarding_slots")
    op.execute("DROP FUNCTION execbound.onboarding_slot_expiry()")
    op.execute("""
        ALTER TABLE execbound.onboarding_slots
            DROP CONSTRAINT onboarding_slots_lifecycle,
            DROP COLUMN converted_at,
            DROP COLUMN deactivated_at,
            DROP COLUMN extended_until,
            DROP COLUMN notice_at,
            DROP COLUMN expires_at
    """)
    op.execute("DROP TABLE execbound.signup_messages")
    op.execute("DROP TABLE execbound.signup_requests")
