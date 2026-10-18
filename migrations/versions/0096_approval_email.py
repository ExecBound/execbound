# SPDX-License-Identifier: AGPL-3.0-only
"""Approval emails: a person's opt-in in a Community workspace, and its outbox (#179).

A person in a hosted Community workspace may turn on one email for each held request they can
decide. `approval_email_subscriptions` holds that opt-in, one row per person per workspace, with
when its current subscription began and how it ended. `approval_emails` is the outbox, in the
approval's own workspace: one row per approval per person (`UNIQUE (tenant_id, approval_id,
principal_id)`), with the deadline it was queued against and the signup outbox's lease and
outcome columns. It holds no address or name: the sender resolves the person's verified account
address when it sends, and keeps only the SHA-256 of each message's one-click unsubscribe secret.

Six definer functions, every one used only by the hosted plugin, so each is created dormant by
the revoke convention of `0063_personal_access_tokens`, as both tables are: no grant but the
owner's, nothing for PUBLIC, the runtime role or a Supabase platform role. The hosted plugin's
upgrade command, `execbound hosted-upgrade`, grants exactly what its `CLAIMS` name.

- `approval_email_change` turns the calling session's own person on or off, inside its fence.
- `approval_email_queue` is the only writer of a new message. Inside one workspace's fence and
  with no actor, it refuses a workspace that is not active and `free`, and queues one message for
  each pending approval with more than fifteen seconds left, held at or after the subscription
  began and within the last hour, for each live subscriber the approval routing join names (an
  active person holding an active scope on the approval's target, action and Space) who has not
  decided it. So the runtime never chooses a recipient, an approval or a deadline.
- `approval_email_tenants`, `approval_email_due` and `approval_email_sent` read across tenants.
  On the hosted database the owner of these functions does not bypass row security, so, as
  `0078_weekly_summary` and `0092_dormancy_warning` do, a SELECT policy granted only to the role
  running this migration (`owner_drain`) lets them read every tenant's rows. They return
  identifiers or one count, never an address or a name.
- `approval_email_unsubscribe` ends a subscription, inside its fence, only for a message whose
  secret matches and that was queued since the subscription's current start, so an old link
  cannot end a renewed subscription.
"""

from alembic import op
from sqlalchemy import text

revision = "0096_approval_email"
down_revision = "0095_scout_audit_retention"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
SUPABASE_ROLES = ("anon", "authenticated", "service_role")
TABLES = ("approval_email_subscriptions", "approval_emails")

SCHEMA = """
CREATE TABLE execbound.approval_email_subscriptions (
    tenant_id uuid NOT NULL REFERENCES execbound.tenants,
    principal_id uuid NOT NULL,
    subscribed_at timestamptz NOT NULL,
    ended_at timestamptz,
    ended_via text CHECK (ended_via IN ('SETTINGS', 'LINK')),
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
    CHECK ((ended_at IS NULL) = (ended_via IS NULL))
);
CREATE INDEX approval_email_subscriptions_live
    ON execbound.approval_email_subscriptions (tenant_id) WHERE ended_at IS NULL;
CREATE TABLE execbound.approval_emails (
    tenant_id uuid NOT NULL,
    email_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    decide_by timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED', 'SKIPPED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    next_attempt_at timestamptz NOT NULL,
    lease_until timestamptz,
    lease_token uuid,
    delivered_at timestamptz,
    last_error text CHECK (last_error IS NULL OR last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    unsubscribe_hash text CHECK (unsubscribe_hash IS NULL OR unsubscribe_hash ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, email_id),
    -- At most one email per approval per person.
    UNIQUE (tenant_id, approval_id, principal_id),
    FOREIGN KEY (tenant_id, approval_id) REFERENCES execbound.approvals,
    FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.approval_email_subscriptions,
    CHECK (decide_by > created_at)
);
CREATE INDEX approval_emails_due ON execbound.approval_emails (next_attempt_at)
    WHERE state IN ('PENDING', 'IN_FLIGHT');
CREATE INDEX approval_emails_delivered ON execbound.approval_emails (delivered_at)
    WHERE state = 'DELIVERED';
-- The per-person caps' count, inside one workspace's fence. Not partial, so it also covers the
-- foreign key to the subscription.
CREATE INDEX approval_emails_person ON execbound.approval_emails (tenant_id, principal_id);
"""

SIGNATURES = (
    "approval_email_change(uuid, boolean, timestamptz)",
    "approval_email_queue(timestamptz)",
    "approval_email_tenants(timestamptz)",
    "approval_email_due(timestamptz, integer)",
    "approval_email_sent(timestamptz, timestamptz)",
    "approval_email_unsubscribe(uuid, text, timestamptz)",
)
# The approval routing rule, `notifications._ASSIGNED` at the time of writing, verbatim: who may
# decide an approval, read over `effective_approval_scopes` (s) and the approval's execution (e).
# A migration never imports application code; a test holds the two equal.
ASSIGNED = (
    "s.tenant_id=e.tenant_id AND s.canonical_target_id=e.canonical_target_id "
    "AND s.action=e.frozen->'intent'->>'action' AND s.space_id=e.space_id"
)

CLOCK = r"""
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
"""

FENCE = r"""
    -- Inside one tenant's fence and nowhere else: every row read and written is that tenant's.
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
"""

CHANGE = (
    r"""
CREATE FUNCTION execbound.approval_email_change(
    p_session uuid, p_on boolean, p_now timestamptz)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_session execbound.human_sessions;
    v_live boolean;
BEGIN
"""
    + FENCE
    + CLOCK
    + r"""
    IF p_on IS NULL THEN
        RAISE EXCEPTION 'INVALID_BODY';
    END IF;
    -- The calling session's own person, checked as `account_change` (0052) checks a session:
    -- live and unexpired, its credential live, its principal active and of its kind, and a
    -- person, never an agent. The caller never names a principal.
    SELECT * INTO v_session FROM execbound.human_sessions
     WHERE tenant_id = v_tenant AND session_id = p_session;
    IF v_session.session_id IS NULL OR v_session.revoked_at IS NOT NULL
       OR p_now < v_session.created_at OR p_now >= v_session.expires_at
       OR v_session.kind NOT IN ('ADMIN', 'HUMAN_APPROVER') OR NOT EXISTS (
           SELECT 1 FROM execbound.credentials c
             JOIN execbound.principals p
               ON p.tenant_id = c.tenant_id AND p.principal_id = c.principal_id
            WHERE c.tenant_id = v_tenant AND c.credential_id = v_session.credential_id
              AND p.active AND c.revoked_at IS NULL AND c.expires_at > p_now
              AND p.kind = v_session.kind)
    THEN
        RAISE EXCEPTION 'INVALID_SESSION';
    END IF;
    SELECT s.ended_at IS NULL INTO v_live FROM execbound.approval_email_subscriptions s
     WHERE s.tenant_id = v_tenant AND s.principal_id = v_session.principal_id
       FOR UPDATE;
    IF coalesce(v_live, false) = p_on THEN
        RAISE EXCEPTION 'CONFLICT';
    END IF;
    IF p_on THEN
        -- Only an active Community workspace offers it; turning it off is always allowed.
        IF NOT EXISTS (SELECT 1 FROM execbound.tenants t
                        WHERE t.tenant_id = v_tenant AND t.active AND t.plan = 'free') THEN
            RAISE EXCEPTION 'INVALID_PLAN';
        END IF;
        -- A renewed subscription starts afresh: nothing held before `p_now` is queued for it,
        -- and no link from a message queued before it can end it. Only an ended row is
        -- renewed: a turn-on that began before another committed the first row finds it live
        -- here, and refuses as the check above would have.
        INSERT INTO execbound.approval_email_subscriptions
            (tenant_id, principal_id, subscribed_at)
        VALUES (v_tenant, v_session.principal_id, p_now)
        ON CONFLICT (tenant_id, principal_id) DO UPDATE
            SET subscribed_at = excluded.subscribed_at, ended_at = NULL, ended_via = NULL
            WHERE execbound.approval_email_subscriptions.ended_at IS NOT NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'CONFLICT';
        END IF;
    ELSE
        UPDATE execbound.approval_email_subscriptions
           SET ended_at = p_now, ended_via = 'SETTINGS'
         WHERE tenant_id = v_tenant AND principal_id = v_session.principal_id;
    END IF;
    RETURN p_on;
END $$
"""
)

QUEUE = (
    r"""
CREATE FUNCTION execbound.approval_email_queue(p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_count integer;
BEGIN
"""
    + FENCE
    + CLOCK
    + r"""
    IF NOT EXISTS (SELECT 1 FROM execbound.tenants t
                    WHERE t.tenant_id = v_tenant AND t.active AND t.plan = 'free') THEN
        RAISE EXCEPTION 'INVALID_PLAN';
    END IF;
    -- One message per pending approval per live subscriber who can decide it now: the routing
    -- rule core's notifications route and decide by, an active person of a kind that decides,
    -- a subscription that began no later than the approval was held and no later than
    -- `p_now`, an approval held in the last hour with more than the fifteen-second lapse
    -- margin left, and no decision of the subscriber's own on it. A second pass, or two at
    -- once, adds nothing. The message is stamped `p_now`, and the pass's re-check and the
    -- one-click stop need that at or after the subscription's start: a subscription begun
    -- after this pass read its clock waits for the next pass, rather than being stopped.
    INSERT INTO execbound.approval_emails
        (tenant_id, email_id, approval_id, principal_id, decide_by, created_at, next_attempt_at)
    SELECT v_tenant, gen_random_uuid(), due.approval_id, due.principal_id, due.expires_at,
           p_now, p_now
      FROM (
        SELECT DISTINCT a.approval_id, sub.principal_id, a.expires_at
          FROM execbound.approvals a
          JOIN execbound.executions e
            ON e.tenant_id = a.tenant_id AND e.execution_id = a.execution_id
          JOIN execbound.effective_approval_scopes s ON """
    + ASSIGNED
    + r"""
          JOIN execbound.approval_email_subscriptions sub
            ON sub.tenant_id = a.tenant_id AND sub.principal_id = s.approver_id
          JOIN execbound.principals p
            ON p.tenant_id = sub.tenant_id AND p.principal_id = sub.principal_id
         WHERE a.tenant_id = v_tenant AND a.state = 'PENDING' AND s.active
           AND a.expires_at > p_now + interval '15 seconds'
           AND a.created_at >= sub.subscribed_at
           AND sub.subscribed_at <= p_now
           AND a.created_at > p_now - interval '1 hour'
           AND sub.ended_at IS NULL
           AND p.active AND p.kind IN ('ADMIN', 'HUMAN_APPROVER')
           AND NOT EXISTS (SELECT 1 FROM execbound.approval_decisions d
                            WHERE d.tenant_id = a.tenant_id AND d.approval_id = a.approval_id
                              AND d.principal_id = sub.principal_id)
      ) due
     ORDER BY due.expires_at, due.approval_id, due.principal_id
    ON CONFLICT (tenant_id, approval_id, principal_id) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$
"""
)

TENANTS = (
    r"""
CREATE FUNCTION execbound.approval_email_tenants(p_now timestamptz)
RETURNS TABLE(tenant_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
"""
    + CLOCK
    + r"""
    -- Identifiers only, through `owner_drain`: which workspaces have anyone subscribed. It
    -- cannot read `tenants` across tenants, so the queue refuses one that no longer qualifies.
    RETURN QUERY
        SELECT DISTINCT s.tenant_id FROM execbound.approval_email_subscriptions s
         WHERE s.ended_at IS NULL
         ORDER BY s.tenant_id;
END $$
"""
)

DUE = (
    r"""
CREATE FUNCTION execbound.approval_email_due(p_now timestamptz, p_limit integer)
RETURNS TABLE(tenant_id uuid, email_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
"""
    + CLOCK
    + r"""
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'INVALID_LIMIT';
    END IF;
    -- Identifiers only, through `owner_drain`; each message is leased in its own tenant. One
    -- workspace at a time, every workspace's first before any workspace's second, so one with
    -- many reviewers cannot hold back another's; within a turn the soonest deadline first.
    RETURN QUERY
        SELECT d.tenant_id, d.email_id FROM (
            SELECT m.tenant_id, m.email_id, m.decide_by,
                   row_number() OVER (PARTITION BY m.tenant_id
                                      ORDER BY m.decide_by, m.email_id) AS turn
              FROM execbound.approval_emails m
             WHERE (m.state = 'PENDING' AND m.next_attempt_at <= p_now)
                OR (m.state = 'IN_FLIGHT' AND m.lease_until <= p_now)
        ) d
         ORDER BY d.turn, d.decide_by, d.email_id
         LIMIT p_limit;
END $$
"""
)

SENT = r"""
CREATE FUNCTION execbound.approval_email_sent(p_since timestamptz, p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- The window's own checks and no five-minute bound, as `dormancy_warnings_sent` has none:
    -- `relay_sent_today` calls this for signup and reset mail with their own clock reading.
    IF p_since IS NULL OR p_now IS NULL OR p_since > now() OR p_since > p_now THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- One count across tenants, for the relay's daily allowance; nothing else leaves. A message
    -- held under a live lease is counted with the delivered ones: it is being sent.
    RETURN (SELECT count(*)::integer FROM execbound.approval_emails m
             WHERE (m.state = 'DELIVERED' AND m.delivered_at > p_since)
                OR (m.state = 'IN_FLIGHT' AND m.lease_until > p_now));
END $$
"""

UNSUBSCRIBE = (
    r"""
CREATE FUNCTION execbound.approval_email_unsubscribe(
    p_email uuid, p_hash text, p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid;
BEGIN
"""
    + FENCE
    + CLOCK
    + r"""
    IF p_email IS NULL OR p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;
    -- The message's own secret, for a subscription still live and begun no later than the
    -- message was queued: an old link cannot end a renewed subscription.
    UPDATE execbound.approval_email_subscriptions s
       SET ended_at = p_now, ended_via = 'LINK'
      FROM execbound.approval_emails m
     WHERE m.tenant_id = v_tenant AND m.email_id = p_email
       AND m.unsubscribe_hash = p_hash
       AND s.tenant_id = m.tenant_id AND s.principal_id = m.principal_id
       AND s.ended_at IS NULL AND m.created_at >= s.subscribed_at
    RETURNING s.principal_id INTO v_principal;
    RETURN v_principal;
END $$
"""
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(SCHEMA)
    roles = [role for role in SUPABASE_ROLES if role_exists(role)]
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON execbound.{table} "
            f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
        )
        # The cross-tenant reads, granted to the role running this migration, which owns every
        # definer function below; the runtime role never matches it, and it is SELECT only.
        op.execute(
            f"CREATE POLICY owner_drain ON execbound.{table} FOR SELECT TO CURRENT_USER "
            "USING (true)"
        )
        # Born dormant: no grant but the owner's, so a runtime with no hosted plugin can neither
        # read a subscription nor learn that a message was ever queued.
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    for body in (CHANGE, QUEUE, TENANTS, DUE, SENT, UNSUBSCRIBE):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")


def downgrade() -> None:
    # A subscription is a person's own choice, and dropping it loses it, so the count must see
    # every workspace's rows. `owner_drain` already shows them to the role that ran the upgrade;
    # FORCE is lifted around the count as well, as 0078's downgrade does, so the refusal does
    # not rest on that policy alone (a table owner it does not name would see nothing
    # unfenced), and put back before anything else happens.
    op.execute("ALTER TABLE execbound.approval_email_subscriptions NO FORCE ROW LEVEL SECURITY")
    populated = (
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM execbound.approval_email_subscriptions)"))
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.approval_email_subscriptions FORCE ROW LEVEL SECURITY")
    if populated:
        raise RuntimeError(
            "Approval email subscriptions require a verified full restore; lossy downgrade refused"
        )
    for signature in reversed(SIGNATURES):
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP TABLE execbound.approval_emails")
    op.execute("DROP TABLE execbound.approval_email_subscriptions")
