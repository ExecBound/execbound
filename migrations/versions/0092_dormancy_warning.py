# SPDX-License-Identifier: AGPL-3.0-only
"""The advance dormancy warning: one email to each live administrator before agents sleep (#439).

A free hosted workspace's agents go to sleep after ninety days with no governed request
(`agents_sleep`, `0044_hosted_free`). Fourteen days before that, at day 76, each of the
workspace's live administrators is sent one warning, once per approach. An approach is named by
its `silent_since`, the moment silence is measured from, so any governed request starts a new
one and nothing is written on the request path.

`dormancy_warnings` is the outbox, in the warned workspace's own tenant: one row per
administrator per approach (`UNIQUE (tenant_id, principal_id, silent_since)`), with the sleep
moment it names and the signup outbox's lease and outcome columns. It holds no address; the
sender resolves one when it sends.

Three definer functions, every one used only by the hosted plugin, so each is created dormant by
the revoke convention of `0063_personal_access_tokens`, as the table is: no grant but the
owner's, nothing for PUBLIC, the runtime role or a Supabase platform role. The hosted plugin's
upgrade command, `execbound hosted-upgrade`, grants exactly what its `CLAIMS` name.

- `dormancy_warn` is the only writer of a new row. Inside one tenant's fence and with no actor,
  it applies `agents_sleep`'s own rule for silence and queues one warning for each live
  administrator when the workspace is between day 76 and day 90, so the runtime can never
  choose a recipient, date a warning or queue one that is not due.
- `dormancy_warnings_due` lists the warnings due for an attempt, one workspace at a time (each
  workspace's first before any workspace's second, and within each turn the soonest sleep
  first), and `dormancy_warnings_sent` counts those delivered since a moment with those a
  drain holds under a lease still live at another, both across tenants. On the hosted
  database the owner of these functions does not bypass row security, so, as
  `0078_weekly_summary` does, a SELECT policy granted only to the role running this migration
  (`owner_drain`) lets them read every tenant's rows. They return identifiers or one count,
  never an address or a name.
"""

from alembic import op
from sqlalchemy import text

revision = "0092_dormancy_warning"
down_revision = "0091_microsoft_sign_in"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
SUPABASE_ROLES = ("anon", "authenticated", "service_role")
SIGNATURES = (
    "dormancy_warn(timestamptz)",
    "dormancy_warnings_due(timestamptz, integer)",
    "dormancy_warnings_sent(timestamptz, timestamptz)",
)

TABLE = """
CREATE TABLE execbound.dormancy_warnings (
    tenant_id uuid NOT NULL REFERENCES execbound.tenants,
    warning_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    silent_since timestamptz NOT NULL,
    sleeps_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED', 'SKIPPED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    next_attempt_at timestamptz NOT NULL,
    lease_until timestamptz,
    lease_token uuid,
    delivered_at timestamptz,
    last_error text CHECK (last_error IS NULL OR last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    PRIMARY KEY (tenant_id, warning_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
    -- Once per approach: one warning per administrator for each moment silence ran from.
    UNIQUE (tenant_id, principal_id, silent_since),
    CHECK (sleeps_at > silent_since)
);
CREATE INDEX dormancy_warnings_due ON execbound.dormancy_warnings (next_attempt_at)
    WHERE state IN ('PENDING', 'IN_FLIGHT');
CREATE INDEX dormancy_warnings_delivered ON execbound.dormancy_warnings (delivered_at)
    WHERE state = 'DELIVERED';
"""

CLOCK = r"""
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
"""

WARN = (
    r"""
CREATE FUNCTION execbound.dormancy_warn(p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_claimed timestamptz;
    v_last timestamptz;
    v_silent_since timestamptz;
    v_count integer;
BEGIN
    -- Inside one tenant's fence and nowhere else: every row read and written is that tenant's.
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
"""
    + CLOCK
    + r"""
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t
         WHERE t.tenant_id = v_tenant AND t.active AND t.plan = 'free'
    ) THEN
        RAISE EXCEPTION 'INVALID_PLAN';
    END IF;
    -- `agents_sleep`'s own measure of silence, so the warning and the sleep cannot disagree:
    -- the later of the claim (or provisioning) and the last execution event that is not the
    -- scheduler's own.
    SELECT coalesce(s.claimed_at, t.provisioned_at) INTO v_claimed
      FROM execbound.tenants t
      LEFT JOIN execbound.onboarding_slots s ON s.tenant_id = t.tenant_id
     WHERE t.tenant_id = v_tenant;
    IF v_claimed IS NULL THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    SELECT max(e.occurred_at) INTO v_last FROM execbound.audit_events e
     WHERE e.tenant_id = v_tenant AND e.kind LIKE 'execution.%'
       AND NOT EXISTS (SELECT 1 FROM execbound.principals s
                        WHERE s.tenant_id = e.tenant_id AND s.principal_id = e.actor_id
                          AND s.kind = 'SYSTEM');
    v_silent_since := greatest(v_claimed, coalesce(v_last, v_claimed));
    -- Nothing would sleep, or the workspace is not between day 76 and day 90.
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.kind = 'AGENT' AND p.active
           AND p.deactivated_at IS NULL
    ) OR v_silent_since > p_now - interval '76 days'
       OR v_silent_since <= p_now - interval '90 days' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- One warning per live administrator, the test `agents_sleep` picks its actor by: an active
    -- person holding workspace-wide `access.manage`. A second pass, or two at once, adds
    -- nothing: the unique key holds the approach.
    INSERT INTO execbound.dormancy_warnings
        (tenant_id, warning_id, principal_id, silent_since, sleeps_at, created_at,
         next_attempt_at)
    SELECT v_tenant, gen_random_uuid(), p.principal_id, v_silent_since,
           v_silent_since + interval '90 days', p_now, p_now
      FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.active AND p.kind NOT IN ('AGENT', 'SYSTEM')
       AND execbound.access_has_permission(p.principal_id, 'access.manage', NULL, false)
     ORDER BY p.principal_id
    ON CONFLICT (tenant_id, principal_id, silent_since) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$
"""
)

DUE = (
    r"""
CREATE FUNCTION execbound.dormancy_warnings_due(p_now timestamptz, p_limit integer)
RETURNS TABLE(tenant_id uuid, warning_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
"""
    + CLOCK
    + r"""
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'INVALID_LIMIT';
    END IF;
    -- Identifiers only, through `owner_drain`; each warning is leased in its own tenant. One
    -- workspace at a time: every workspace's first due warning before any workspace's second,
    -- so one with many administrators cannot hold back another's. Within a turn, the soonest
    -- sleep first: a warning still waiting at its sleep moment is skipped, never sent late, so
    -- when the relay's share runs short the workspaces with least time left go first.
    RETURN QUERY
        SELECT d.tenant_id, d.warning_id FROM (
            SELECT w.tenant_id, w.warning_id, w.sleeps_at, w.next_attempt_at,
                   row_number() OVER (PARTITION BY w.tenant_id
                                      ORDER BY w.next_attempt_at, w.warning_id) AS turn
              FROM execbound.dormancy_warnings w
             WHERE (w.state = 'PENDING' AND w.next_attempt_at <= p_now)
                OR (w.state = 'IN_FLIGHT' AND w.lease_until <= p_now)
        ) d
         ORDER BY d.turn, d.sleeps_at, d.next_attempt_at, d.warning_id
         LIMIT p_limit;
END $$
"""
)

SENT = r"""
CREATE FUNCTION execbound.dormancy_warnings_sent(p_since timestamptz, p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_since IS NULL OR p_now IS NULL OR p_since > now() OR p_since > p_now THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- One count across tenants, for the relay's daily allowance; nothing else leaves. A
    -- warning a drain holds under a live lease is counted with the delivered ones: it is being
    -- sent, and another drain must not spend the same room.
    RETURN (SELECT count(*)::integer FROM execbound.dormancy_warnings w
             WHERE (w.state = 'DELIVERED' AND w.delivered_at > p_since)
                OR (w.state = 'IN_FLIGHT' AND w.lease_until > p_now));
END $$
"""


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(TABLE)
    roles = [role for role in SUPABASE_ROLES if role_exists(role)]
    op.execute("ALTER TABLE execbound.dormancy_warnings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.dormancy_warnings FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON execbound.dormancy_warnings "
        f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
    )
    # The cross-tenant reads, granted to the role running this migration, which owns every
    # definer function below; the runtime role never matches it, and it is SELECT only.
    op.execute(
        "CREATE POLICY owner_drain ON execbound.dormancy_warnings FOR SELECT TO CURRENT_USER "
        "USING (true)"
    )
    # Born dormant: no grant but the owner's, so a runtime with no hosted plugin can neither
    # read a warning nor learn that one was ever queued.
    op.execute("REVOKE ALL ON execbound.dormancy_warnings FROM PUBLIC, execbound_app")
    for role in roles:
        op.execute(f"REVOKE ALL ON execbound.dormancy_warnings FROM {role}")
    for body in (WARN, DUE, SENT):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")


def downgrade() -> None:
    # Warnings not yet sent are not sent; nothing else references the table.
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP TABLE execbound.dormancy_warnings")
