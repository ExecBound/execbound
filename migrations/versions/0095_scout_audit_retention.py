# SPDX-License-Identifier: AGPL-3.0-only
"""The retention of a directory's audit observations and the bound's episode (#355).

`monitor_audit_purge` is the one way the runtime removes an observation; the runtime still holds
no `DELETE` on any table. Inside the caller's own tenant fence, and only for a Microsoft Entra
connection of that tenant, which it locks, it deletes the listed observations that are, all at
once, of the directory's audit log (`entra_audit`), evaluated, stamped at least thirty days of
24 hours (`reach.EVIDENCE_VALIDITY`, whatever the session's time zone) before the statement's
moment by the database's own clock, so the runtime cannot make current evidence look old, and
cited by no finding; it returns how many it deleted, and leaves any other listed id alone. It
refuses a tenant fence that is missing or names a workspace that is not active, a list that is
missing or longer than 1,000, and a connection it does not admit.
Which old observations the rules still need, an actor's baseline and an execution's other
observations, the store chooses; this function bounds what any caller can remove. It runs as
its owner on a fixed search path; `PUBLIC` and the Supabase platform roles hold nothing on it,
and the runtime holds `EXECUTE`.

`monitor_observations_entra_actor` indexes a directory's audit observations by actor, action
and moment, for the store's choice of what the purge keeps and the bound's test of an actor's
first action.

`monitor_connections` gains, for an Entra connection only, `audit_bound_since`: the moment the
connection's reads began meeting its observation bound, set by the first read the bound applies
to and cleared by the first that ends with the connection a tenth of the bound under it, which
dates the episode a `collection-health.v1` finding is raised for. The runtime gains column
`UPDATE` on it and no `INSERT`. No table or policy is added.

The downgrade drops the three. What the purge deleted is gone, which no downgrade can restore,
so nothing refuses.
"""

from alembic import op
from sqlalchemy import text

revision = "0095_scout_audit_retention"
down_revision = "0094_scout_audit"
branch_labels = None
depends_on = None

SIGNATURE = "monitor_audit_purge(uuid, uuid[])"
SUPABASE_ROLES = ("anon", "authenticated", "service_role")

PURGE = r"""
CREATE FUNCTION execbound.monitor_audit_purge(p_connection uuid, p_observations uuid[])
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_count integer;
BEGIN
    -- Inside one active workspace's fence and nowhere else.
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_observations IS NULL OR cardinality(p_observations) > 1000 THEN
        RAISE EXCEPTION 'INVALID_LIMIT';
    END IF;
    -- A Microsoft Entra connection of this workspace, locked as a read's write locks it, so no
    -- read stores an observation while its purge runs.
    PERFORM 1 FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = p_connection
       AND c.kind = 'entra_agent_id'
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- Only what no rule reads: the directory's audit log, evaluated, past the thirty days
    -- evidence stays current by this clock, and cited by no finding. The thirty days are 720
    -- hours, the rules' own horizon: an interval of days would keep the wall-clock time in the
    -- session's time zone and be an hour short across a change of its clocks.
    DELETE FROM execbound.monitor_observations o
     WHERE o.tenant_id = v_tenant AND o.connection_id = p_connection
       AND o.observation_id = ANY(p_observations)
       AND o.kind = 'entra_audit'
       AND o.evaluation_state = 'COMPLETED'
       AND o.occurred_at <= statement_timestamp() - interval '720 hours'
       AND NOT EXISTS (
           SELECT 1 FROM execbound.monitor_findings f
            WHERE f.tenant_id = o.tenant_id AND f.observation_id = o.observation_id);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$
"""


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(PURGE)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM PUBLIC")
    for role in SUPABASE_ROLES:
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{SIGNATURE} TO execbound_app")
    op.execute("""
        CREATE INDEX monitor_observations_entra_actor ON execbound.monitor_observations
            (tenant_id, connection_id, actor_ref, action, occurred_at)
            WHERE kind = 'entra_audit'
    """)
    op.execute("""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN audit_bound_since timestamptz,
            ADD CONSTRAINT monitor_connections_audit_bound_kind
                CHECK (audit_bound_since IS NULL OR kind = 'entra_agent_id')
    """)
    op.execute("GRANT UPDATE (audit_bound_since) ON execbound.monitor_connections TO execbound_app")


def downgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.monitor_connections "
        "DROP CONSTRAINT monitor_connections_audit_bound_kind, "
        "DROP COLUMN audit_bound_since"
    )
    op.execute("DROP INDEX execbound.monitor_observations_entra_actor")
    op.execute(f"DROP FUNCTION execbound.{SIGNATURE}")
