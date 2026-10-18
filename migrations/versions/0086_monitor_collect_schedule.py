# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring collection on a schedule: a connection's mode, its intervals, a request and a lease.

`monitor_connections` gains:

- `credential_mode`, how the connection authenticates. Every row is `key_file` (the operator's
  key file, with only its fingerprint in the database), the only mode this revision admits.
- `collect_interval_seconds` and `activity_interval_seconds`. Null means the kind's default.
  Entra reads its directory every 3,600 to 86,400 seconds; Tines reads its inventory daily,
  which is not adjustable, and its audit records every 300 to 3,600 seconds. Entra has no
  activity interval.
- `collect_requested_at` and `collect_requested_by`: an administrator asked for a collection
  ("Collect now"). A request is not a collection; the next scheduled pass picks it up.
- `collecting_until` and `collecting_lease`: one run holds the connection until then, and proves
  it with the lease id whenever it writes, so two runs never collect one connection at once and
  a run that outlived its lease cannot overwrite the next one's work.

`last_outcome` admits `INTERRUPTED`, which a claim records for a lease that expired unfinished.

Four definer functions are the only writers of the new columns: `admin_request_collection` and
`admin_set_collection_schedule` for an active administrator of the connection's space, and
`collector_claim` and `collector_release` for a collection run. A claim takes a duration of
at most fifteen minutes and measures it from the database's own clock; no function takes a
time from its caller. A trigger clears the lease in the statement that revokes a connection.

The runtime keeps `SELECT` on every column. Its table-level `INSERT` becomes column-level
`INSERT` on exactly the columns that existed before this revision, so the operator's
`create-connection` still inserts and nothing can insert a scheduled, requested or leased
row; it may update none of the new columns. `check_runtime` holds the database to both.

The downgrade refuses while any connection records `INTERRUPTED`, which the schema below this
revision cannot express; otherwise it drops the columns, functions and index and restores the
table-level grant and the previous outcome check. A schedule, a pending request or a held lease
is not evidence, and is dropped with its column.
"""

from alembic import op
from sqlalchemy import text

revision = "0086_monitor_collect_schedule"
down_revision = "0085_account_recovery"
branch_labels = None
depends_on = None

# Every column of `monitor_connections` before this revision: the runtime's insertable set.
INSERTABLE = (
    "tenant_id, connection_id, label, base_url, team_id, key_fingerprint, created_at, "
    "created_by, active, revoked_at, capabilities, capabilities_at, health_state, "
    "health_changed_at, audit_cursor, platform_tenant_ref, last_run_at, last_run_id, "
    "last_outcome, last_error_code, last_sync_at, retry_after_seconds, "
    "consecutive_rate_limited, consecutive_backlog, kind, directory_ref, client_ref, space_id"
)
OUTCOMES = "'COMPLETE', 'BACKLOG', 'RATE_LIMITED', 'AUTH_LOST', 'RETENTION_GAP', 'ERROR'"

# An active administrator of an active tenant: the actor check of `admin_credential_replaces`
# (0079), which never admits an agent or a workspace's scheduler principal.
ACTOR = """
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor AND p.active
           AND p.kind NOT IN ('AGENT', 'SYSTEM')
           AND execbound.access_effective_kind(p_actor) = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

# The active connection, locked, in a space the actor administers: the monitoring store's own
# space rule (`_check_connection_space`), where a membership narrows the tenant's ADMIN and a
# reviewer's seat never grants collector administration.
CONNECTION = """
    SELECT c.kind, c.space_id INTO v_kind, v_space FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = p_connection AND c.active
       FOR UPDATE;
    IF v_kind IS NULL THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.space_members m
         WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
    ) AND NOT EXISTS (
        SELECT 1 FROM execbound.space_members m
         WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
           AND m.space_id = v_space AND m.role = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

REQUEST = f"""
CREATE FUNCTION execbound.admin_request_collection(p_actor uuid, p_connection uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
    v_space uuid;
BEGIN
    {ACTOR}
    {CONNECTION}
    -- A request already waiting is the one the next pass answers; a second changes nothing.
    UPDATE execbound.monitor_connections
       SET collect_requested_at = now(), collect_requested_by = p_actor
     WHERE tenant_id = v_tenant AND connection_id = p_connection
       AND collect_requested_at IS NULL;
END $$
"""

SCHEDULE = f"""
CREATE FUNCTION execbound.admin_set_collection_schedule(
    p_actor uuid, p_connection uuid, p_collect integer, p_activity integer)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
    v_space uuid;
BEGIN
    {ACTOR}
    {CONNECTION}
    -- Null is the kind's default. Entra: a full collection every one to twenty-four hours and
    -- no activity interval. Tines: the inventory daily, as it always has been, and its audit
    -- records every five to sixty minutes.
    IF (v_kind = 'entra_agent_id'
            AND ((p_collect IS NOT NULL AND p_collect NOT BETWEEN 3600 AND 86400)
                 OR p_activity IS NOT NULL))
        OR (v_kind = 'tines'
            AND ((p_collect IS NOT NULL AND p_collect <> 86400)
                 OR (p_activity IS NOT NULL AND p_activity NOT BETWEEN 300 AND 3600))) THEN
        RAISE EXCEPTION 'INVALID_SCHEDULE';
    END IF;
    UPDATE execbound.monitor_connections
       SET collect_interval_seconds = p_collect, activity_interval_seconds = p_activity
     WHERE tenant_id = v_tenant AND connection_id = p_connection;
END $$
"""

CLAIM = """
CREATE FUNCTION execbound.collector_claim(p_connection uuid, p_lease uuid, p_seconds integer)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_until timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    -- No caller holds a connection longer than fifteen minutes, measured by this clock.
    IF p_lease IS NULL OR p_seconds IS NULL OR p_seconds NOT BETWEEN 60 AND 900 THEN
        RAISE EXCEPTION 'INVALID_LEASE';
    END IF;
    SELECT c.collecting_until INTO v_until
      FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = p_connection AND c.active
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF v_until > now() THEN
        RETURN jsonb_build_object('claimed', false);
    END IF;
    IF v_until IS NOT NULL THEN
        -- A run that held the lease and never released it: recorded, so the page says the
        -- run stopped rather than showing the outcome of the run before it.
        UPDATE execbound.monitor_connections
           SET last_outcome = 'INTERRUPTED', last_error_code = 'RUN_INTERRUPTED',
               health_changed_at = CASE WHEN health_state = 'ERROR'
                                        THEN coalesce(health_changed_at, now()) ELSE now() END,
               health_state = 'ERROR'
         WHERE tenant_id = v_tenant AND connection_id = p_connection;
    END IF;
    -- A request made before this claim is answered by this run; one made after survives it.
    UPDATE execbound.monitor_connections
       SET collecting_until = now() + make_interval(secs => p_seconds),
           collecting_lease = p_lease,
           collect_requested_by = CASE WHEN collect_requested_at <= now() THEN NULL
                                       ELSE collect_requested_by END,
           collect_requested_at = CASE WHEN collect_requested_at <= now() THEN NULL
                                       ELSE collect_requested_at END
     WHERE tenant_id = v_tenant AND connection_id = p_connection;
    RETURN jsonb_build_object('claimed', true);
END $$
"""

RELEASE = """
CREATE FUNCTION execbound.collector_release(p_connection uuid, p_lease uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.monitor_connections
       SET collecting_until = NULL, collecting_lease = NULL
     WHERE tenant_id = v_tenant AND connection_id = p_connection
       AND collecting_lease = p_lease;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'LEASE_LOST';
    END IF;
END $$
"""

# Revoking a connection ends its lease in the revoking statement itself. The runtime may update
# none of the lease columns, so the statement that sets `active` false cannot name them; this
# trigger clears them, and a run that still holds the lease then writes nothing more and its
# release finds nothing to return.
UNLEASED = """
CREATE FUNCTION execbound.monitor_connections_revoked_unleased()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT NEW.active THEN
        NEW.collecting_until := NULL;
        NEW.collecting_lease := NULL;
    END IF;
    RETURN NEW;
END $$
"""

SIGNATURES = (
    "admin_request_collection(uuid, uuid)",
    "admin_set_collection_schedule(uuid, uuid, integer, integer)",
    "collector_claim(uuid, uuid, integer)",
    "collector_release(uuid, uuid)",
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(f"""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN credential_mode text NOT NULL DEFAULT 'key_file',
            ADD COLUMN collect_interval_seconds integer,
            ADD COLUMN activity_interval_seconds integer,
            ADD COLUMN collect_requested_at timestamptz,
            ADD COLUMN collect_requested_by uuid,
            ADD COLUMN collecting_until timestamptz,
            ADD COLUMN collecting_lease uuid,
            ADD CONSTRAINT monitor_connections_credential_mode_check
                CHECK (credential_mode IN ('key_file')),
            ADD CONSTRAINT monitor_connections_collect_interval CHECK (
                collect_interval_seconds IS NULL
                OR (kind = 'entra_agent_id' AND collect_interval_seconds BETWEEN 3600 AND 86400)
                OR (kind = 'tines' AND collect_interval_seconds = 86400)
            ),
            ADD CONSTRAINT monitor_connections_activity_interval CHECK (
                activity_interval_seconds IS NULL
                OR (kind = 'tines' AND activity_interval_seconds BETWEEN 300 AND 3600)
            ),
            ADD CONSTRAINT monitor_connections_request_pair
                CHECK ((collect_requested_at IS NULL) = (collect_requested_by IS NULL)),
            ADD CONSTRAINT monitor_connections_lease_pair
                CHECK ((collecting_until IS NULL) = (collecting_lease IS NULL)),
            ADD CONSTRAINT monitor_connections_collect_requested_by_fkey
                FOREIGN KEY (tenant_id, collect_requested_by)
                REFERENCES execbound.principals(tenant_id, principal_id),
            DROP CONSTRAINT monitor_connections_last_outcome_check,
            ADD CONSTRAINT monitor_connections_last_outcome_check
                CHECK (last_outcome IN ({OUTCOMES}, 'INTERRUPTED'))
    """)
    op.execute(
        "CREATE INDEX monitor_connections_collect_requested_by "
        "ON execbound.monitor_connections (tenant_id, collect_requested_by)"
    )
    # Revoking the table-level grant revokes every column-level one with it, so the columns
    # the runtime may insert are granted again by name.
    op.execute("REVOKE INSERT ON execbound.monitor_connections FROM execbound_app")
    op.execute(f"GRANT INSERT ({INSERTABLE}) ON execbound.monitor_connections TO execbound_app")
    for body in (REQUEST, SCHEDULE, CLAIM, RELEASE, UNLEASED):
        op.execute(body)
    # Callable by no one: a trigger runs it, and no grant is needed for that.
    op.execute(
        "REVOKE ALL ON FUNCTION execbound.monitor_connections_revoked_unleased() FROM PUBLIC"
    )
    op.execute(
        "CREATE TRIGGER monitor_connections_revoked_unleased "
        "BEFORE UPDATE OF active ON execbound.monitor_connections "
        "FOR EACH ROW EXECUTE FUNCTION execbound.monitor_connections_revoked_unleased()"
    )
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    op.execute("LOCK TABLE execbound.monitor_connections IN ACCESS EXCLUSIVE MODE")
    # The hosted owner does not bypass row security, so under FORCE this check would see no
    # tenant's rows and pass; lift it, as 0030's downgrade does, and put it back below.
    op.execute("ALTER TABLE execbound.monitor_connections NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    if (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_connections "
                "WHERE last_outcome = 'INTERRUPTED')"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError("Cannot downgrade while an interrupted collection run is recorded")
    op.execute("DROP TRIGGER monitor_connections_revoked_unleased ON execbound.monitor_connections")
    op.execute("DROP FUNCTION execbound.monitor_connections_revoked_unleased()")
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP INDEX execbound.monitor_connections_collect_requested_by")
    op.execute(f"""
        ALTER TABLE execbound.monitor_connections
            DROP CONSTRAINT monitor_connections_last_outcome_check,
            ADD CONSTRAINT monitor_connections_last_outcome_check
                CHECK (last_outcome IN ({OUTCOMES})),
            DROP CONSTRAINT monitor_connections_collect_requested_by_fkey,
            DROP COLUMN collecting_lease,
            DROP COLUMN collecting_until,
            DROP COLUMN collect_requested_by,
            DROP COLUMN collect_requested_at,
            DROP COLUMN activity_interval_seconds,
            DROP COLUMN collect_interval_seconds,
            DROP COLUMN credential_mode
    """)
    # The column-level grants go with the table-level revoke, so the runtime is left with the
    # one table-level grant it held before this revision and no column grant beside it.
    op.execute("REVOKE INSERT ON execbound.monitor_connections FROM execbound_app")
    op.execute("GRANT INSERT ON execbound.monitor_connections TO execbound_app")
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.monitor_connections FORCE ROW LEVEL SECURITY")
