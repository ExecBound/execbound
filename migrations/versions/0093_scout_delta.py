# SPDX-License-Identifier: AGPL-3.0-only
"""Scout delta collection and the new-actor rules (#355).

`monitor_connections` gains, for an Entra connection only:

- `delta_link`: the `servicePrincipals/delta` link a delta pass reads next. It is the pinned Graph
  origin and the delta path with the query Graph gave, at most 4,096 characters, and only on a
  connection that has a baseline; the collector rebuilds it from those parts and validates it
  again before every use, so this check is the database's copy of the rule, not the rule.
- `delta_at`: when that link last advanced.
- `baseline_at`: the end of the connection's first complete collection that read both its
  principal collections. Every principal first seen at or before it is part of the baseline, and
  none of the three rules below speaks about it. The upgrade sets it to the upgrade's own moment
  on every Entra connection that has synchronized, whatever its latest collection's outcome, so
  nothing collected before it becomes news; the one exception is a connection that holds no
  classic service principal, so never read the service principals, which list every principal
  in a directory. It, and one that never synchronized, takes its baseline at its first collection
  that reads both, because the store lacks every principal it never read, which a later read
  would otherwise call new.

`monitor_agents` gains `ai_publisher`, the AI publisher catalog's key for the principal's
application (never an identifier it matched on), and one episode marker per rule:
`new_actor_opened_at`, `first_action_opened_at` and `ai_consent_opened_at`.

`monitor_findings` admits four rules. `new-actor.v1`, `first-consequential-action.v1` and
`new-ai-consent.v1` name an agent; `initial-inventory.v1` names a connection and nothing else.
Every one but `first-consequential-action.v1` carries no observation; that one carries the
observation it was raised on, which the existing foreign key holds to the agent's connection.
`new-agent.v1` stays admitted, so every finding it raised stays readable.

A delta pass holds the connection's lease like any run, and `collecting_delta` says that the
lease is a delta pass's. `collector_claim_delta` is the only claim that sets it: it takes the
lease only for an Entra connection with a link and a baseline and with no collection request
waiting, and it leaves every request where it is, because a delta pass answers none. A delta
pass records no outcome when it finishes, so one that dies holding the lease records none
either: `collector_claim` records `INTERRUPTED` only for a full run's expired lease, and
`collector_claim_delta` records it for one too, returns that lease and takes nothing, so an
interrupted run is followed by a full collection. `collector_release` and the revoke trigger
clear the mark with the lease. The runtime may write none of it.

The runtime gains column `UPDATE` on the seven new columns and no `INSERT` on the three
connection columns or the lease mark, so `check_runtime`'s insertable set is unchanged, and
`EXECUTE` on `collector_claim_delta`. No table, policy or index is added. The downgrade refuses
`SCOUT_DELTA_FINDINGS_RETAINED` while any finding of the four rules is retained, looking with row
security off for the look alone because an owner that does not bypass it would otherwise see
nothing; a delta link, a baseline, a lease mark and an episode marker are state rather than
evidence, and are dropped with their columns, and the three lease functions are restored as
0086 wrote them.
"""

import importlib.util
from pathlib import Path
from types import ModuleType

from alembic import op
from sqlalchemy import text

revision = "0093_scout_delta"
down_revision = "0092_dormancy_warning"
branch_labels = None
depends_on = None

DELTA_PREFIX = "https://graph.microsoft.com/v1.0/servicePrincipals/delta?"
PUBLISHER = "^[a-z][a-z0-9-]{0,31}$"
CONNECTION_COLUMNS = ("delta_link", "delta_at", "baseline_at")
AGENT_COLUMNS = (
    "ai_publisher",
    "new_actor_opened_at",
    "first_action_opened_at",
    "ai_consent_opened_at",
)
NEW_RULES = (
    "'new-actor.v1', 'first-consequential-action.v1', 'new-ai-consent.v1', 'initial-inventory.v1'"
)

PRIOR_SCOUT = "'ungoverned-reach.v1', 'sponsorless-agent.v1', 'new-agent.v1'"
PRIOR_COLLECTION = "'instrumentation-gap.v1', 'collection-health.v1'"
PRIOR_WITHOUT_OBSERVATION = "'source-health.v1', " + PRIOR_COLLECTION + ", " + PRIOR_SCOUT
PRIOR_RULES = (
    "'sensitive-action.v1', 'sensitive-action.v2', 'source-event-integrity.v1', "
    "'source-health.v1', 'clock-skew.v1', 'restricted-target.v1', 'observed-rate.v1', "
    "'monitored-path-change.v1', " + PRIOR_COLLECTION + ", " + PRIOR_SCOUT
)

AGENT_RULES = PRIOR_SCOUT + ", 'new-actor.v1', 'first-consequential-action.v1', 'new-ai-consent.v1'"
WITHOUT_OBSERVATION = (
    PRIOR_WITHOUT_OBSERVATION + ", 'new-actor.v1', 'new-ai-consent.v1', 'initial-inventory.v1'"
)
FINDING_RULES = PRIOR_RULES + ", " + NEW_RULES

TABLES = ("monitor_connections", "monitor_agents", "monitor_findings")

# A run that held the lease and never released it, as 0086 records one: the page then says the
# run stopped rather than showing the outcome of the run before it.
INTERRUPTED = """UPDATE execbound.monitor_connections
           SET last_outcome = 'INTERRUPTED', last_error_code = 'RUN_INTERRUPTED',
               health_changed_at = CASE WHEN health_state = 'ERROR'
                                        THEN coalesce(health_changed_at, now()) ELSE now() END,
               health_state = 'ERROR'"""

LEASE_CHECKS = """IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    -- No caller holds a connection longer than fifteen minutes, measured by this clock.
    IF p_lease IS NULL OR p_seconds IS NULL OR p_seconds NOT BETWEEN 60 AND 900 THEN
        RAISE EXCEPTION 'INVALID_LEASE';
    END IF;"""

CLAIM = f"""
CREATE OR REPLACE FUNCTION execbound.collector_claim(
    p_connection uuid, p_lease uuid, p_seconds integer
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_until timestamptz;
    v_delta boolean;
BEGIN
    {LEASE_CHECKS}
    SELECT c.collecting_until, c.collecting_delta INTO v_until, v_delta
      FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = p_connection AND c.active
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF v_until > now() THEN
        RETURN jsonb_build_object('claimed', false);
    END IF;
    -- A full run that held the lease and never released it is recorded. A delta pass records
    -- no outcome when it finishes, so one that stopped records none either.
    IF v_until IS NOT NULL AND NOT v_delta THEN
        {INTERRUPTED}
         WHERE tenant_id = v_tenant AND connection_id = p_connection;
    END IF;
    -- A request made before this claim is answered by this run; one made after survives it.
    UPDATE execbound.monitor_connections
       SET collecting_until = now() + make_interval(secs => p_seconds),
           collecting_lease = p_lease,
           collecting_delta = false,
           collect_requested_by = CASE WHEN collect_requested_at <= now() THEN NULL
                                       ELSE collect_requested_by END,
           collect_requested_at = CASE WHEN collect_requested_at <= now() THEN NULL
                                       ELSE collect_requested_at END
     WHERE tenant_id = v_tenant AND connection_id = p_connection;
    RETURN jsonb_build_object('claimed', true);
END $$
"""

CLAIM_DELTA = f"""
CREATE FUNCTION execbound.collector_claim_delta(
    p_connection uuid, p_lease uuid, p_seconds integer
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_until timestamptz;
    v_delta boolean;
    v_kind text;
    v_link text;
    v_baseline timestamptz;
    v_requested timestamptz;
BEGIN
    {LEASE_CHECKS}
    SELECT c.collecting_until, c.collecting_delta, c.kind, c.delta_link, c.baseline_at,
           c.collect_requested_at
      INTO v_until, v_delta, v_kind, v_link, v_baseline, v_requested
      FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = p_connection AND c.active
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF v_until > now() THEN
        RETURN jsonb_build_object('claimed', false);
    END IF;
    IF v_until IS NOT NULL AND NOT v_delta THEN
        -- A full run that held the lease and never released it: recorded as `collector_claim`
        -- records it, and its lease returned. A full collection follows an interrupted run,
        -- never a delta pass.
        {INTERRUPTED},
               collecting_until = NULL, collecting_lease = NULL
         WHERE tenant_id = v_tenant AND connection_id = p_connection;
        RETURN jsonb_build_object('claimed', false);
    END IF;
    -- A directory with a link and a baseline, and no request waiting: a delta pass answers no
    -- request, so this claim leaves every one where it is, for a full collection.
    IF v_kind <> 'entra_agent_id' OR v_link IS NULL OR v_baseline IS NULL
       OR v_requested IS NOT NULL THEN
        RETURN jsonb_build_object('claimed', false);
    END IF;
    UPDATE execbound.monitor_connections
       SET collecting_until = now() + make_interval(secs => p_seconds),
           collecting_lease = p_lease,
           collecting_delta = true
     WHERE tenant_id = v_tenant AND connection_id = p_connection;
    RETURN jsonb_build_object('claimed', true);
END $$
"""

RELEASE = """
CREATE OR REPLACE FUNCTION execbound.collector_release(p_connection uuid, p_lease uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.monitor_connections
       SET collecting_until = NULL, collecting_lease = NULL, collecting_delta = false
     WHERE tenant_id = v_tenant AND connection_id = p_connection
       AND collecting_lease = p_lease;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'LEASE_LOST';
    END IF;
END $$
"""

UNLEASED = """
CREATE OR REPLACE FUNCTION execbound.monitor_connections_revoked_unleased()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT NEW.active THEN
        NEW.collecting_until := NULL;
        NEW.collecting_lease := NULL;
        NEW.collecting_delta := false;
    END IF;
    RETURN NEW;
END $$
"""

CLAIM_DELTA_SIGNATURE = "collector_claim_delta(uuid, uuid, integer)"


def _schedule_0086() -> ModuleType:
    """0086's module, for the text of the lease functions this revision replaces."""
    spec = importlib.util.spec_from_file_location(
        "monitor_collect_schedule", Path(__file__).with_name("0086_monitor_collect_schedule.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _findings_constraints(agent_rules: str, without_observation: str, rules: str) -> str:
    return f"""
        ALTER TABLE execbound.monitor_findings
            DROP CONSTRAINT monitor_findings_agent_rule,
            ADD CONSTRAINT monitor_findings_agent_rule
                CHECK ((agent_id IS NOT NULL) = (rule_version IN ({agent_rules}))),
            DROP CONSTRAINT monitor_findings_health_without_observation,
            ADD CONSTRAINT monitor_findings_health_without_observation
                CHECK ((observation_id IS NULL) = (rule_version IN ({without_observation}))),
            DROP CONSTRAINT monitor_findings_rule_version_check,
            ADD CONSTRAINT monitor_findings_rule_version_check
                CHECK (rule_version IN ({rules}))
    """


def upgrade() -> None:
    op.execute(f"""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN delta_link text,
            ADD COLUMN delta_at timestamptz,
            ADD COLUMN baseline_at timestamptz,
            ADD CONSTRAINT monitor_connections_delta_link CHECK (
                delta_link IS NULL OR (
                    kind = 'entra_agent_id'
                    AND length(delta_link) <= 4096
                    AND starts_with(delta_link, '{DELTA_PREFIX}')
                    AND baseline_at IS NOT NULL
                )
            ),
            ADD CONSTRAINT monitor_connections_baseline_kind
                CHECK (baseline_at IS NULL OR kind = 'entra_agent_id'),
            ADD CONSTRAINT monitor_connections_delta_at_kind
                CHECK (delta_at IS NULL OR kind = 'entra_agent_id'),
            ADD COLUMN collecting_delta boolean NOT NULL DEFAULT false,
            ADD CONSTRAINT monitor_connections_delta_lease
                CHECK (NOT collecting_delta OR collecting_lease IS NOT NULL)
    """)
    for body in (CLAIM, CLAIM_DELTA, RELEASE, UNLEASED):
        op.execute(body)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{CLAIM_DELTA_SIGNATURE} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role"):
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{CLAIM_DELTA_SIGNATURE} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{CLAIM_DELTA_SIGNATURE} TO execbound_app")
    op.execute(f"""
        ALTER TABLE execbound.monitor_agents
            ADD COLUMN ai_publisher text CHECK (ai_publisher ~ '{PUBLISHER}'),
            ADD COLUMN new_actor_opened_at timestamptz,
            ADD COLUMN first_action_opened_at timestamptz,
            ADD COLUMN ai_consent_opened_at timestamptz
    """)
    op.execute(_findings_constraints(AGENT_RULES, WITHOUT_OBSERVATION, FINDING_RULES))
    op.execute(
        f"GRANT UPDATE ({', '.join(CONNECTION_COLUMNS)}) "
        "ON execbound.monitor_connections TO execbound_app"
    )
    op.execute(
        f"GRANT UPDATE ({', '.join(AGENT_COLUMNS)}) ON execbound.monitor_agents TO execbound_app"
    )

    # The baseline of every Entra connection that has synchronized is this upgrade, whatever its
    # latest collection's outcome: the store holds what its collections read, and a principal
    # that appears after it is news. The exception is a connection that never read the service
    # principals, which list every principal in a directory, agent identities among them. It
    # holds no classic principal, and every principal a later read stores for the first time
    # was there all along and would be called new, so it takes its baseline at its first
    # collection that reads both. A collection marks a principal it did not list gone and keeps
    # it, so a stored classic principal is the fact, never the latest run's outcome or probe.
    # The hosted owner does not bypass row security, so under FORCE this would see no tenant and
    # baseline nothing; lift it on both tables for this statement alone, as 0088 does, and put
    # it back.
    op.execute(
        "LOCK TABLE execbound.monitor_connections, execbound.monitor_agents "
        "IN ACCESS EXCLUSIVE MODE"
    )
    for table in ("monitor_connections", "monitor_agents"):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    op.execute(
        "UPDATE execbound.monitor_connections c SET baseline_at = now() "
        "WHERE c.kind = 'entra_agent_id' AND c.last_sync_at IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM execbound.monitor_agents a "
        "WHERE a.tenant_id = c.tenant_id AND a.connection_id = c.connection_id "
        "AND a.identity_class = 'service_principal')"
    )
    op.execute("SET LOCAL row_security = on")
    for table in ("monitor_connections", "monitor_agents"):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"execbound.{table}" for table in TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    # The look sees every tenant: the hosted owner does not bypass row security.
    op.execute("ALTER TABLE execbound.monitor_findings NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_findings "
                f"WHERE rule_version IN ({NEW_RULES}))"
            )
        )
        .scalar_one()
    )
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.monitor_findings FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "SCOUT_DELTA_FINDINGS_RETAINED: findings of the delta rules are retained, and the "
            "earlier finding checks cannot hold them"
        )
    op.execute(_findings_constraints(PRIOR_SCOUT, PRIOR_WITHOUT_OBSERVATION, PRIOR_RULES))
    # The lease functions as 0086 wrote them, before the mark they read goes.
    prior = _schedule_0086()
    for body in (prior.CLAIM, prior.RELEASE, prior.UNLEASED):
        op.execute(body.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
    op.execute(f"DROP FUNCTION execbound.{CLAIM_DELTA_SIGNATURE}")
    op.execute(
        "ALTER TABLE execbound.monitor_agents "
        + ", ".join(f"DROP COLUMN {column}" for column in AGENT_COLUMNS)
    )
    op.execute(
        "ALTER TABLE execbound.monitor_connections "
        "DROP CONSTRAINT monitor_connections_delta_link, "
        "DROP CONSTRAINT monitor_connections_baseline_kind, "
        "DROP CONSTRAINT monitor_connections_delta_at_kind, "
        "DROP CONSTRAINT monitor_connections_delta_lease, "
        "DROP COLUMN collecting_delta, "
        + ", ".join(f"DROP COLUMN {column}" for column in CONNECTION_COLUMNS)
    )
