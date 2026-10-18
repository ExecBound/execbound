# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary: a person's opt-in, and its own outbox (#678).

A person turns the summary on under My account. Each Monday one message per active
subscription is queued in that subscriber's workspace and drained like the teammate
invitation outbox: leased, attempted with backoff, settled with a code-shaped error.

Delivery must reach workspaces no jobs token names, and on the hosted database and Community
the owner of these functions does not bypass row security. So only identifiers cross tenants:
`weekly_summary_tenants` lists the workspaces with an active subscription, `weekly_summary_due`
the messages due, and `weekly_summary_sent` counts deliveries for the deployment's daily cap,
each through a SELECT policy granted only to the role that runs this migration and owns every
function here. Every write, the enqueue included, happens inside one tenant's own fence:
`weekly_summary_enqueue` and `weekly_summary_unsubscribe` read their tenant from
`execbound.tenant_id` and refuse to run without one.

The unsubscribe link carries a fresh 256-bit secret per message; only its SHA-256 is kept,
and a link ends a subscription only when its message was queued at or after the
subscription's current start, so an old link cannot end a renewed subscription.
"""

from alembic import op
from sqlalchemy import text

revision = "0078_weekly_summary"
down_revision = "0077_rejection_index"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
SUBSCRIPTION = ("subscribed_at", "ended_at", "ended_via")
DELIVERY = (
    "state",
    "attempts",
    "next_attempt_at",
    "lease_until",
    "lease_token",
    "delivered_at",
    "last_error",
    "unsubscribe_hash",
)
SIGNATURES = (
    "weekly_summary_tenants(timestamptz)",
    "weekly_summary_enqueue(date, timestamptz)",
    "weekly_summary_due(timestamptz, integer)",
    "weekly_summary_sent(timestamptz)",
    "weekly_summary_unsubscribe(uuid, text, timestamptz)",
)

TABLES = """
CREATE TABLE execbound.weekly_summary_subscriptions (
    tenant_id uuid NOT NULL REFERENCES execbound.tenants,
    principal_id uuid NOT NULL,
    subscribed_at timestamptz NOT NULL,
    ended_at timestamptz,
    ended_via text CHECK (ended_via IN ('SETTINGS', 'LINK')),
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
    CHECK ((ended_at IS NULL) = (ended_via IS NULL))
);
CREATE INDEX weekly_summary_subscriptions_active
    ON execbound.weekly_summary_subscriptions (tenant_id) WHERE ended_at IS NULL;
CREATE TABLE execbound.weekly_summary_messages (
    tenant_id uuid NOT NULL,
    message_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    week_ending date NOT NULL CHECK (extract(isodow FROM week_ending) = 1),
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
    PRIMARY KEY (tenant_id, message_id),
    UNIQUE (tenant_id, principal_id, week_ending),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.weekly_summary_subscriptions
);
CREATE INDEX weekly_summary_messages_due ON execbound.weekly_summary_messages (next_attempt_at)
    WHERE state IN ('PENDING', 'IN_FLIGHT');
CREATE INDEX weekly_summary_messages_delivered
    ON execbound.weekly_summary_messages (delivered_at) WHERE state = 'DELIVERED';
"""

CLOCK = r"""
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
"""

TENANTS = (
    r"""
CREATE FUNCTION execbound.weekly_summary_tenants(p_now timestamptz)
RETURNS TABLE(tenant_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
"""
    + CLOCK
    + r"""
    -- Identifiers only, through `owner_drain`: which workspaces have anyone subscribed.
    RETURN QUERY
        SELECT DISTINCT s.tenant_id FROM execbound.weekly_summary_subscriptions s
         WHERE s.ended_at IS NULL
         ORDER BY s.tenant_id;
END $$
"""
)

ENQUEUE = (
    r"""
CREATE FUNCTION execbound.weekly_summary_enqueue(p_week date, p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_count integer;
BEGIN
    -- Inside one tenant's fence and nowhere else: every row read and written is that
    -- tenant's, so the tenant policy passes whatever the owner's bypass.
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'TENANT_REQUIRED';
    END IF;
"""
    + CLOCK
    + r"""
    IF p_week IS NULL OR extract(isodow FROM p_week) <> 1
       OR p_week > (p_now AT TIME ZONE 'UTC')::date THEN
        RAISE EXCEPTION 'INVALID_WEEK';
    END IF;
    INSERT INTO execbound.weekly_summary_messages
        (tenant_id, message_id, principal_id, week_ending, created_at, next_attempt_at)
    SELECT s.tenant_id, gen_random_uuid(), s.principal_id, p_week, p_now, p_now
      FROM execbound.weekly_summary_subscriptions s
      JOIN execbound.principals p
        ON p.tenant_id = s.tenant_id AND p.principal_id = s.principal_id
      JOIN execbound.tenants t ON t.tenant_id = s.tenant_id
     WHERE s.tenant_id = v_tenant AND s.ended_at IS NULL AND t.active AND p.active
       AND p.kind IN ('ADMIN', 'HUMAN_APPROVER')
    ON CONFLICT (tenant_id, principal_id, week_ending) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$
"""
)

DUE = (
    r"""
CREATE FUNCTION execbound.weekly_summary_due(p_now timestamptz, p_limit integer)
RETURNS TABLE(tenant_id uuid, message_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
"""
    + CLOCK
    + r"""
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'INVALID_LIMIT';
    END IF;
    -- Identifiers only, through `owner_drain`; each message is leased in its own tenant.
    RETURN QUERY
        SELECT m.tenant_id, m.message_id FROM execbound.weekly_summary_messages m
         WHERE (m.state = 'PENDING' AND m.next_attempt_at <= p_now)
            OR (m.state = 'IN_FLIGHT' AND m.lease_until <= p_now)
         ORDER BY m.next_attempt_at, m.message_id
         LIMIT p_limit;
END $$
"""
)

SENT = r"""
CREATE FUNCTION execbound.weekly_summary_sent(p_since timestamptz)
RETURNS integer
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_since IS NULL OR p_since > now() THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- One count across tenants, for the deployment's daily cap; nothing else leaves.
    RETURN (SELECT count(*)::integer FROM execbound.weekly_summary_messages m
             WHERE m.state = 'DELIVERED' AND m.delivered_at > p_since);
END $$
"""

UNSUBSCRIBE = (
    r"""
CREATE FUNCTION execbound.weekly_summary_unsubscribe(
    p_message uuid, p_hash text, p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'TENANT_REQUIRED';
    END IF;
"""
    + CLOCK
    + r"""
    IF p_message IS NULL OR p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;
    -- The message's own secret, for a subscription still active and started no later than
    -- the message was queued: an old link cannot end a renewed subscription.
    UPDATE execbound.weekly_summary_subscriptions s
       SET ended_at = p_now, ended_via = 'LINK'
      FROM execbound.weekly_summary_messages m
     WHERE m.tenant_id = v_tenant AND m.message_id = p_message
       AND m.unsubscribe_hash = p_hash
       AND s.tenant_id = m.tenant_id AND s.principal_id = m.principal_id
       AND s.ended_at IS NULL AND m.created_at >= s.subscribed_at
    RETURNING s.principal_id INTO v_principal;
    RETURN v_principal;
END $$
"""
)


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
    # The cross-tenant reads, granted to the role running this migration, which owns every
    # definer function below; the runtime role never matches it, and it is SELECT only.
    op.execute(
        f"CREATE POLICY owner_drain ON execbound.{table} FOR SELECT TO CURRENT_USER USING (true)"
    )


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(TABLES)
    for table in ("weekly_summary_subscriptions", "weekly_summary_messages"):
        protect(table)
    op.execute("GRANT INSERT ON execbound.weekly_summary_subscriptions TO execbound_app")
    op.execute(
        "GRANT UPDATE (" + ", ".join(SUBSCRIPTION) + ") "
        "ON execbound.weekly_summary_subscriptions TO execbound_app"
    )
    op.execute(
        "GRANT UPDATE (" + ", ".join(DELIVERY) + ") "
        "ON execbound.weekly_summary_messages TO execbound_app"
    )
    for body in (TENANTS, ENQUEUE, DUE, SENT, UNSUBSCRIBE):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    # An owner that does not bypass row security sees no tenant's subscription unfenced, so
    # FORCE is lifted around the count and put back before anything else happens.
    op.execute("ALTER TABLE execbound.weekly_summary_subscriptions NO FORCE ROW LEVEL SECURITY")
    populated = (
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM execbound.weekly_summary_subscriptions)"))
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.weekly_summary_subscriptions FORCE ROW LEVEL SECURITY")
    if populated:
        raise RuntimeError(
            "Weekly summaries require a verified full restore; lossy downgrade refused"
        )
    for signature in reversed(SIGNATURES):
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP POLICY owner_drain ON execbound.weekly_summary_messages")
    op.execute("DROP POLICY owner_drain ON execbound.weekly_summary_subscriptions")
    op.execute("DROP TABLE execbound.weekly_summary_messages")
    op.execute("DROP TABLE execbound.weekly_summary_subscriptions")
