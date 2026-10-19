# SPDX-License-Identifier: AGPL-3.0-only
"""Scout's Agents page as the to-do list, and the synthetic directory (#355, step 4).

`monitor_agents`:

- `identity_class` gains `managed_identity` (the directory states the type `ManagedIdentity`)
  and `consented_app` (another organization's application holding an application or delegated
  permission grant), which the runtime may now update: within the classic family a principal
  moves as its type and its consents do, and `monitor_agents_class_family` refuses any other
  move (`CLASS_FIXED`), so an agent identity or a Tines story never moves and nothing becomes
  one.
- `app_ref` keeps the principal's application id, a GUID or nothing, so that the page can say
  what to filter the admin center's enterprise applications by. The runtime inserts it by its
  table grant and updates it.

`monitor_connections` gains the synthetic directory: kind `fixture`, credential mode
`synthetic`, held to each other, with no key and the one fixed shape, a base address that
resolves nowhere and a synthetic directory and client. Every check that names the Entra kind
for a column the synthetic directory writes widens to both directory kinds; the delta link and
its moment stay Entra's. One active synthetic directory per workspace
(`monitor_connections_one_synthetic`), and a trigger, `monitor_connections_directory_coexist`,
refuses a synthetic directory in a workspace holding any Microsoft Entra connection
(`DIRECTORY_CONNECTED`) and a Microsoft Entra connection beside an active synthetic directory
(`SYNTHETIC_DIRECTORY_PRESENT`), under the connection registry lock, whichever path inserts.
`admin_add_synthetic_directory` is the one writer of one: the runtime inserts no credential mode.

Two triggers keep a synthetic directory's evidence out of real work: `agent_bindings` refuses to
bind its actor (`SYNTHETIC_ACTOR`), whichever path binds, and `monitor_deliveries` refuses a
destination's delivery of its finding (`SYNTHETIC_DIRECTORY`); routing closes the intent first.
Both run as their invoker.

`monitor_reach_acceptances` records every acceptance and withdrawal of an ungoverned path, who
and when, with its reason code and expiry, append-only under forced row security; the runtime
reads it. `admin_accept_reach` and `admin_withdraw_reach` are the only writers of it and of
`monitor_reach_exceptions`, on which the runtime loses `INSERT` and its `UPDATE` of
`withdrawn_at`: a renewal now sets the reason, the expiry, who and when, and clears the
withdrawal, which the runtime's conflict clause never could.

`monitor_audit_purge` admits both directory kinds, so a synthetic directory's observations are
purged by the same rules, and `admin_set_collection_schedule` holds the synthetic directory to a
real directory's schedule, a full collection every one to twenty-four hours and no activity
interval, refusing anything else `INVALID_SCHEDULE` before the table's check would.

The downgrade refuses `SCOUT_AGENTS_PAGE_RETAINED` while any synthetic connection or acceptance
history is retained, looking with row security off for the look alone because an owner that
does not bypass it would otherwise see nothing. Otherwise it maps both new classes back to
`service_principal`, the class they had, which the next collection under the earlier code
derives again, drops `app_ref`, and restores every check, the purge, the schedule rule, the
grants and the functions.
"""

from alembic import op
from sqlalchemy import text

revision = "0099_scout_agents_page"
down_revision = "0098_scout_drivers"
branch_labels = None
depends_on = None

SUPABASE_ROLES = ("anon", "authenticated", "service_role")
GUID = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
# The synthetic directory's one shape, which `monitoring.synthetic` holds too: an address in the
# reserved `.invalid` domain, which resolves nowhere, and a directory and client no directory
# holds.
SYNTHETIC_BASE = "https://synthetic-directory.invalid"
SYNTHETIC_DIRECTORY = "5c007000-0000-4000-8000-000000000001"
SYNTHETIC_CLIENT = "5c007000-0000-4000-8000-000000000002"
SYNTHETIC_LABEL = "Synthetic directory"
DIRECTORIES = "('entra_agent_id', 'fixture')"

ADD = "admin_add_synthetic_directory(uuid, uuid, uuid)"
ACCEPT = "admin_accept_reach(uuid, uuid, text, text, text, text, timestamp with time zone)"
WITHDRAW = "admin_withdraw_reach(uuid, uuid, text, text, text)"
DEFINERS = (ADD, ACCEPT, WITHDRAW)
# Each trigger: its table, its name (its function's too) and the event it fires before.
TRIGGERS = (
    ("monitor_connections", "monitor_connections_directory_coexist", "INSERT"),
    ("agent_bindings", "agent_bindings_not_synthetic", "INSERT"),
    ("monitor_deliveries", "monitor_deliveries_not_synthetic", "INSERT"),
    ("monitor_agents", "monitor_agents_class_family", "UPDATE OF identity_class"),
)
PURGE_SIGNATURE = "execbound.monitor_audit_purge(uuid, uuid[])"
PURGE_ENTRA = "AND c.kind = 'entra_agent_id'"
PURGE_DIRECTORIES = f"AND c.kind IN {DIRECTORIES}"
# 0086's schedule rule: the synthetic directory is collected on a real directory's schedule, so
# an interval outside it is `INVALID_SCHEDULE` from the function, not the table's check failing.
SCHEDULE_SIGNATURE = "execbound.admin_set_collection_schedule(uuid, uuid, integer, integer)"
SCHEDULE_ENTRA = "IF (v_kind = 'entra_agent_id'"
SCHEDULE_DIRECTORIES = f"IF (v_kind IN {DIRECTORIES}"

# Each check this revision replaces: its name, what it held before, and what it holds now.
CHECKS = (
    (
        "monitor_agents",
        "monitor_agents_identity_class_check",
        "identity_class IN ('agent_identity', 'service_principal', 'tines_story')",
        "identity_class IN ('agent_identity', 'service_principal', 'managed_identity', "
        "'consented_app', 'tines_story')",
    ),
    (
        "monitor_connections",
        "monitor_connections_kind_check",
        "kind IN ('tines', 'entra_agent_id')",
        "kind IN ('tines', 'entra_agent_id', 'fixture')",
    ),
    (
        "monitor_connections",
        "monitor_connections_credential_mode_check",
        "credential_mode IN ('key_file', 'sealed', 'platform_app')",
        "credential_mode IN ('key_file', 'sealed', 'platform_app', 'synthetic')",
    ),
    (
        "monitor_connections",
        "monitor_connections_platform_keyless",
        "(credential_mode = 'platform_app') = (key_fingerprint IS NULL)",
        "(credential_mode IN ('platform_app', 'synthetic')) = (key_fingerprint IS NULL)",
    ),
    (
        "monitor_connections",
        "monitor_connections_base_url_check",
        "(kind = 'tines' AND base_url ~ "
        r"'^https://[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.tines\.(com|io)$') "
        "OR (kind = 'entra_agent_id' AND base_url = 'https://graph.microsoft.com')",
        "(kind = 'tines' AND base_url ~ "
        r"'^https://[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.tines\.(com|io)$') "
        "OR (kind = 'entra_agent_id' AND base_url = 'https://graph.microsoft.com') "
        f"OR (kind = 'fixture' AND base_url = '{SYNTHETIC_BASE}')",
    ),
    (
        "monitor_connections",
        "monitor_connections_baseline_kind",
        "baseline_at IS NULL OR kind = 'entra_agent_id'",
        f"baseline_at IS NULL OR kind IN {DIRECTORIES}",
    ),
    (
        "monitor_connections",
        "monitor_connections_audit_baseline_kind",
        "audit_baseline_at IS NULL OR kind = 'entra_agent_id'",
        f"audit_baseline_at IS NULL OR kind IN {DIRECTORIES}",
    ),
    (
        "monitor_connections",
        "monitor_connections_audit_behind_kind",
        "audit_behind_since IS NULL OR kind = 'entra_agent_id'",
        f"audit_behind_since IS NULL OR kind IN {DIRECTORIES}",
    ),
    (
        "monitor_connections",
        "monitor_connections_audit_bound_kind",
        "audit_bound_since IS NULL OR kind = 'entra_agent_id'",
        f"audit_bound_since IS NULL OR kind IN {DIRECTORIES}",
    ),
    (
        "monitor_connections",
        "monitor_connections_sign_in_kind",
        "sign_in_cursor IS NULL OR kind = 'entra_agent_id'",
        f"sign_in_cursor IS NULL OR kind IN {DIRECTORIES}",
    ),
    (
        "monitor_connections",
        "monitor_connections_directory_kind",
        "(kind = 'entra_agent_id') = (directory_ref IS NOT NULL AND client_ref IS NOT NULL)",
        f"(kind IN {DIRECTORIES}) = (directory_ref IS NOT NULL AND client_ref IS NOT NULL)",
    ),
    (
        "monitor_connections",
        "monitor_connections_collect_interval",
        "collect_interval_seconds IS NULL "
        "OR (kind = 'entra_agent_id' AND collect_interval_seconds BETWEEN 3600 AND 86400) "
        "OR (kind = 'tines' AND collect_interval_seconds = 86400)",
        "collect_interval_seconds IS NULL "
        f"OR (kind IN {DIRECTORIES} AND collect_interval_seconds BETWEEN 3600 AND 86400) "
        "OR (kind = 'tines' AND collect_interval_seconds = 86400)",
    ),
)
# The checks this revision adds and the downgrade drops.
NEW_CHECKS = (
    (
        "monitor_agents",
        "monitor_agents_app_ref_check",
        f"app_ref ~ '{GUID}'",
    ),
    (
        "monitor_connections",
        "monitor_connections_synthetic_kind",
        "(credential_mode = 'synthetic') = (kind = 'fixture')",
    ),
    (
        "monitor_connections",
        "monitor_connections_synthetic_shape",
        f"kind <> 'fixture' OR (base_url = '{SYNTHETIC_BASE}' "
        f"AND directory_ref = '{SYNTHETIC_DIRECTORY}' AND client_ref = '{SYNTHETIC_CLIENT}' "
        f"AND team_id IS NULL AND label = '{SYNTHETIC_LABEL}')",
    ),
)

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"

HISTORY = r"""
CREATE TABLE execbound.monitor_reach_acceptances (
    tenant_id uuid NOT NULL,
    acceptance_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$'),
    path_kind text NOT NULL
        CHECK (path_kind IN ('grant', 'role', 'inherited', 'execbound', 'observation')),
    path_ref text NOT NULL CHECK (path_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    change text NOT NULL CHECK (change IN ('accepted', 'withdrawn')),
    reason_code text CHECK (reason_code ~ '^[A-Z_]{1,48}$'),
    expires_at timestamptz,
    recorded_by uuid NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, acceptance_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES execbound.monitor_agents (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, recorded_by)
        REFERENCES execbound.principals (tenant_id, principal_id),
    -- An acceptance names its reason, a withdrawal neither a reason nor an expiry.
    CHECK ((change = 'accepted') = (reason_code IS NOT NULL)),
    CHECK (change = 'accepted' OR expires_at IS NULL),
    CHECK (expires_at IS NULL OR expires_at > recorded_at)
);
CREATE INDEX monitor_reach_acceptances_agent
    ON execbound.monitor_reach_acceptances (tenant_id, agent_id, recorded_at);
CREATE INDEX monitor_reach_acceptances_recorded_by
    ON execbound.monitor_reach_acceptances (tenant_id, recorded_by);
"""

# The checks every administration function here makes first: an active workspace fence, and an
# active human administrator of it.
_PREAMBLE = """
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor AND p.active
           AND p.kind NOT IN ('AGENT', 'SYSTEM')
           AND execbound.access_effective_kind(p_actor) = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""
# An administrator narrowed to Spaces, in the words `space_create` uses since 0047 and 0073
# repeats: no workspace-wide `access.manage`, and a membership of any Space. The synthetic
# directory is the whole workspace's, since while it is present no Space connects Microsoft
# Entra and adding it asks whether any Space ever did, so only a workspace administrator adds it.
_WORKSPACE_ADMIN = """
    IF NOT execbound.access_has_permission(p_actor, 'access.manage', NULL, false) AND EXISTS (
        SELECT 1 FROM execbound.space_members m
         WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""
# A membership narrows the tenant's ADMIN to the Spaces it administers (0086's rule).
_ADMINISTERS = """
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

ADD_FUNCTION = f"""
CREATE FUNCTION execbound.admin_add_synthetic_directory(
    p_actor uuid, p_space uuid, p_connection uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_space uuid := p_space;
    v_archived boolean;
BEGIN
{_PREAMBLE}
{_WORKSPACE_ADMIN}
    IF p_connection IS NULL THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
    -- The connection registry lock every writer of a connection takes, so the capacity, the
    -- one-per-workspace rule and the coexistence rule are read once each, in order.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('monitor-connections:' || v_tenant::text, 0));
    SELECT s.archived_at IS NOT NULL INTO v_archived FROM execbound.spaces s
     WHERE s.tenant_id = v_tenant AND s.space_id = v_space;
    IF v_archived IS NULL THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    IF v_archived THEN
        RAISE EXCEPTION 'SPACE_ARCHIVED';
    END IF;
{_ADMINISTERS}
    -- The store's MAX_CONNECTIONS, revoked connections counted as the store counts them.
    IF (SELECT count(*) FROM execbound.monitor_connections c
         WHERE c.tenant_id = v_tenant) >= 20 THEN
        RAISE EXCEPTION 'CONNECTION_CAPACITY';
    END IF;
    -- Never beside a real directory, connected now or ever: synthetic and real actors never
    -- share a list.
    IF EXISTS (
        SELECT 1 FROM execbound.monitor_connections c
         WHERE c.tenant_id = v_tenant AND c.kind = 'entra_agent_id'
    ) THEN
        RAISE EXCEPTION 'DIRECTORY_CONNECTED';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.monitor_connections c
         WHERE c.tenant_id = v_tenant AND c.kind = 'fixture' AND c.active
    ) THEN
        RAISE EXCEPTION 'CONNECTION_EXISTS';
    END IF;
    -- The one shape, no key, and its first collection asked for by whoever added it.
    INSERT INTO execbound.monitor_connections
        (tenant_id, connection_id, label, base_url, created_at, created_by, kind,
         directory_ref, client_ref, space_id, credential_mode, collect_requested_at,
         collect_requested_by)
    VALUES (v_tenant, p_connection, '{SYNTHETIC_LABEL}', '{SYNTHETIC_BASE}', now(), p_actor,
            'fixture', '{SYNTHETIC_DIRECTORY}', '{SYNTHETIC_CLIENT}', v_space, 'synthetic',
            now(), p_actor);
END $$
"""

# The agent and the Space of its connection, for both acceptance functions: an actor of this
# workspace, and for an acceptance one still in its directory.
_AGENT = """
    SELECT c.space_id, a.gone_at IS NOT NULL INTO v_space, v_gone
      FROM execbound.monitor_agents a
      JOIN execbound.monitor_connections c
        ON c.tenant_id = a.tenant_id AND c.connection_id = a.connection_id
     WHERE a.tenant_id = v_tenant AND a.agent_id = p_agent
       FOR SHARE OF a;
    IF v_space IS NULL THEN
        RAISE EXCEPTION 'INVALID_AGENT';
    END IF;
"""
_PATH = r"""
    IF p_action IS NULL OR p_action !~ '^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$'
       OR p_kind IS NULL
       OR p_kind NOT IN ('grant', 'role', 'inherited', 'execbound', 'observation')
       OR p_path IS NULL OR p_path !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
"""

ACCEPT_FUNCTION = f"""
CREATE FUNCTION execbound.admin_accept_reach(
    p_actor uuid, p_agent uuid, p_action text, p_kind text, p_path text, p_reason text,
    p_expires timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_space uuid;
    v_gone boolean;
BEGIN
{_PREAMBLE}
{_PATH}
    IF p_reason IS NULL OR p_reason !~ '^[A-Z_]{{1,48}}$'
       OR (p_expires IS NOT NULL AND p_expires <= now()) THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
{_AGENT}
    IF v_gone THEN
        RAISE EXCEPTION 'INVALID_AGENT';
    END IF;
{_ADMINISTERS}
    -- A renewal is a new decision: its reason, expiry, author and moment replace the last, and
    -- a withdrawal before it no longer stands.
    INSERT INTO execbound.monitor_reach_exceptions
        (tenant_id, agent_id, action, path_kind, path_ref, accepted_by, accepted_at,
         expires_at, reason_code)
    VALUES (v_tenant, p_agent, p_action, p_kind, p_path, p_actor, now(), p_expires, p_reason)
    ON CONFLICT (tenant_id, agent_id, action, path_kind, path_ref) DO UPDATE
       SET accepted_by = EXCLUDED.accepted_by, accepted_at = EXCLUDED.accepted_at,
           expires_at = EXCLUDED.expires_at, reason_code = EXCLUDED.reason_code,
           withdrawn_at = NULL;
    INSERT INTO execbound.monitor_reach_acceptances
        (tenant_id, acceptance_id, agent_id, action, path_kind, path_ref, change,
         reason_code, expires_at, recorded_by, recorded_at)
    VALUES (v_tenant, gen_random_uuid(), p_agent, p_action, p_kind, p_path, 'accepted',
            p_reason, p_expires, p_actor, now());
END $$
"""

WITHDRAW_FUNCTION = f"""
CREATE FUNCTION execbound.admin_withdraw_reach(
    p_actor uuid, p_agent uuid, p_action text, p_kind text, p_path text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_space uuid;
    v_gone boolean;
BEGIN
{_PREAMBLE}
{_PATH}
{_AGENT}
{_ADMINISTERS}
    UPDATE execbound.monitor_reach_exceptions SET withdrawn_at = now()
     WHERE tenant_id = v_tenant AND agent_id = p_agent AND action = p_action
       AND path_kind = p_kind AND path_ref = p_path AND withdrawn_at IS NULL;
    IF NOT FOUND THEN
        -- Nothing stands to withdraw.
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    INSERT INTO execbound.monitor_reach_acceptances
        (tenant_id, acceptance_id, agent_id, action, path_kind, path_ref, change,
         recorded_by, recorded_at)
    VALUES (v_tenant, gen_random_uuid(), p_agent, p_action, p_kind, p_path, 'withdrawn',
            p_actor, now());
END $$
"""

COEXIST = """
CREATE FUNCTION execbound.monitor_connections_directory_coexist()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.kind NOT IN ('entra_agent_id', 'fixture') THEN
        RETURN NEW;
    END IF;
    -- The connection registry lock, which every writer of a connection takes already, so two
    -- inserts racing cannot both find the other absent.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('monitor-connections:' || NEW.tenant_id::text, 0));
    IF NEW.kind = 'fixture' AND EXISTS (
        SELECT 1 FROM execbound.monitor_connections c
         WHERE c.tenant_id = NEW.tenant_id AND c.kind = 'entra_agent_id'
    ) THEN
        RAISE EXCEPTION 'DIRECTORY_CONNECTED';
    END IF;
    IF NEW.kind = 'entra_agent_id' AND EXISTS (
        SELECT 1 FROM execbound.monitor_connections c
         WHERE c.tenant_id = NEW.tenant_id AND c.kind = 'fixture' AND c.active
    ) THEN
        RAISE EXCEPTION 'SYNTHETIC_DIRECTORY_PRESENT';
    END IF;
    RETURN NEW;
END $$
"""

NOT_BOUND = """
CREATE FUNCTION execbound.agent_bindings_not_synthetic()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- A synthetic directory's actor exists nowhere: governing it would make a real agent with a
    -- real key for it.
    IF EXISTS (
        SELECT 1 FROM execbound.monitor_agents a
          JOIN execbound.monitor_connections c
            ON c.tenant_id = a.tenant_id AND c.connection_id = a.connection_id
         WHERE a.tenant_id = NEW.tenant_id AND a.agent_id = NEW.agent_id
           AND c.kind = 'fixture'
    ) THEN
        RAISE EXCEPTION 'SYNTHETIC_ACTOR';
    END IF;
    RETURN NEW;
END $$
"""

CLASS_FAMILY = """
CREATE FUNCTION execbound.monitor_agents_class_family()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- A class moves only within the classic family, as a principal's stated type and its
    -- consents do; an agent identity or a Tines story never moves, and nothing becomes one.
    IF NEW.identity_class IS DISTINCT FROM OLD.identity_class AND NOT (
        OLD.identity_class IN ('service_principal', 'managed_identity', 'consented_app')
        AND NEW.identity_class IN ('service_principal', 'managed_identity', 'consented_app')
    ) THEN
        RAISE EXCEPTION 'CLASS_FIXED';
    END IF;
    RETURN NEW;
END $$
"""

NOT_SENT = """
CREATE FUNCTION execbound.monitor_deliveries_not_synthetic()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- A finding a synthetic directory raised, by its connection or its actor's, is never sent
    -- anywhere; routing closes its intent before it would get here.
    IF NEW.destination_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM execbound.monitor_findings f
          LEFT JOIN execbound.monitor_agents a
            ON a.tenant_id = f.tenant_id AND a.agent_id = f.agent_id
          JOIN execbound.monitor_connections c
            ON c.tenant_id = f.tenant_id
           AND c.connection_id = coalesce(f.connection_id, a.connection_id)
         WHERE f.tenant_id = NEW.tenant_id AND f.finding_id = NEW.finding_id
           AND c.kind = 'fixture'
    ) THEN
        RAISE EXCEPTION 'SYNTHETIC_DIRECTORY';
    END IF;
    RETURN NEW;
END $$
"""


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _revoke_function(signature: str) -> None:
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
    for role in SUPABASE_ROLES:
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")


def _replace_kind_test(signature: str, old: str, new: str, refusal: str) -> None:
    """A function as it stands, with its one kind test swapped: the rest of the function, its
    owner and its grants stay exactly as they are."""
    definition = (
        op.get_bind()
        .execute(
            text("SELECT pg_get_functiondef(to_regprocedure(:signature))"),
            {"signature": signature},
        )
        .scalar_one()
    )
    if definition.count(old) != 1:
        raise RuntimeError(refusal)
    op.execute(definition.replace(old, new))


def _replace_purge(old: str, new: str) -> None:
    """`monitor_audit_purge` (0095) with its kind test swapped."""
    _replace_kind_test(
        PURGE_SIGNATURE, old, new, "SCOUT_PURGE_UNEXPECTED: monitor_audit_purge is not 0095's"
    )


def _replace_schedule(old: str, new: str) -> None:
    """`admin_set_collection_schedule` (0086) with its directory kind test swapped."""
    _replace_kind_test(
        SCHEDULE_SIGNATURE,
        old,
        new,
        "SCOUT_SCHEDULE_UNEXPECTED: admin_set_collection_schedule is not 0086's",
    )


def upgrade() -> None:
    for table, name, _, now in CHECKS:
        op.execute(
            f"ALTER TABLE execbound.{table} DROP CONSTRAINT {name}, "
            f"ADD CONSTRAINT {name} CHECK ({now})"
        )
    op.execute("ALTER TABLE execbound.monitor_agents ADD COLUMN app_ref text")
    for table, name, check in NEW_CHECKS:
        op.execute(f"ALTER TABLE execbound.{table} ADD CONSTRAINT {name} CHECK ({check})")
    op.execute(
        "GRANT UPDATE (identity_class, app_ref) ON execbound.monitor_agents TO execbound_app"
    )
    op.execute(
        "CREATE UNIQUE INDEX monitor_connections_one_synthetic "
        "ON execbound.monitor_connections (tenant_id) WHERE active AND kind = 'fixture'"
    )

    op.execute(HISTORY)
    op.execute("ALTER TABLE execbound.monitor_reach_acceptances ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.monitor_reach_acceptances FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.monitor_reach_acceptances
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    op.execute("REVOKE ALL ON execbound.monitor_reach_acceptances FROM PUBLIC")
    for role in SUPABASE_ROLES:
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.monitor_reach_acceptances FROM {role}")
    op.execute("GRANT SELECT ON execbound.monitor_reach_acceptances TO execbound_app")
    # The two functions below are the only writers of an acceptance.
    op.execute("REVOKE INSERT ON execbound.monitor_reach_exceptions FROM execbound_app")
    op.execute(
        "REVOKE UPDATE (withdrawn_at) ON execbound.monitor_reach_exceptions FROM execbound_app"
    )

    for definition in (ADD_FUNCTION, ACCEPT_FUNCTION, WITHDRAW_FUNCTION):
        op.execute(definition)
    for signature in DEFINERS:
        _revoke_function(signature)
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")

    for definition in (COEXIST, NOT_BOUND, NOT_SENT, CLASS_FAMILY):
        op.execute(definition)
    for table, name, event in TRIGGERS:
        op.execute(
            f"CREATE TRIGGER {name} BEFORE {event} ON execbound.{table} "
            f"FOR EACH ROW EXECUTE FUNCTION execbound.{name}()"
        )
        _revoke_function(f"{name}()")

    _replace_purge(PURGE_ENTRA, PURGE_DIRECTORIES)
    _replace_schedule(SCHEDULE_ENTRA, SCHEDULE_DIRECTORIES)


def downgrade() -> None:
    op.execute(
        "LOCK TABLE execbound.monitor_connections, execbound.monitor_agents, "
        "execbound.monitor_reach_acceptances IN ACCESS EXCLUSIVE MODE"
    )
    # The look and the class mapping see every tenant: the hosted owner does not bypass row
    # security.
    looked = ("monitor_connections", "monitor_agents", "monitor_reach_acceptances")
    for table in looked:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_connections "
                "WHERE kind = 'fixture') "
                "OR EXISTS (SELECT 1 FROM execbound.monitor_reach_acceptances)"
            )
        )
        .scalar_one()
    )
    if not retained:
        # The class each had under the earlier schema, which its collection derives again.
        op.execute(
            "UPDATE execbound.monitor_agents SET identity_class = 'service_principal' "
            "WHERE identity_class IN ('managed_identity', 'consented_app')"
        )
    op.execute("SET LOCAL row_security = on")
    for table in looked:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "SCOUT_AGENTS_PAGE_RETAINED: a synthetic directory or an acceptance's history is "
            "retained, and the earlier schema cannot hold it"
        )
    _replace_schedule(SCHEDULE_DIRECTORIES, SCHEDULE_ENTRA)
    _replace_purge(PURGE_DIRECTORIES, PURGE_ENTRA)
    for table, name, _ in TRIGGERS:
        op.execute(f"DROP TRIGGER {name} ON execbound.{table}")
        op.execute(f"DROP FUNCTION execbound.{name}()")
    for signature in DEFINERS:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("GRANT INSERT ON execbound.monitor_reach_exceptions TO execbound_app")
    op.execute("GRANT UPDATE (withdrawn_at) ON execbound.monitor_reach_exceptions TO execbound_app")
    op.execute("DROP TABLE execbound.monitor_reach_acceptances")
    op.execute("DROP INDEX execbound.monitor_connections_one_synthetic")
    op.execute(
        "REVOKE UPDATE (identity_class, app_ref) ON execbound.monitor_agents FROM execbound_app"
    )
    for table, name, _ in reversed(NEW_CHECKS):
        op.execute(f"ALTER TABLE execbound.{table} DROP CONSTRAINT {name}")
    op.execute("ALTER TABLE execbound.monitor_agents DROP COLUMN app_ref")
    for table, name, before, _ in reversed(CHECKS):
        op.execute(
            f"ALTER TABLE execbound.{table} DROP CONSTRAINT {name}, "
            f"ADD CONSTRAINT {name} CHECK ({before})"
        )
