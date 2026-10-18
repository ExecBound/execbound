"""Scheduled jobs for every workspace (#503): the directory of tenants and the scheduler principal.

`job_tenants` lists every tenant once. An invoker trigger on `tenants` adds each new one; every
path that inserts a tenant has already set `execbound.tenant_id` to it, because `tenants`
forces its own policy, so the insert passes this table's `tenant_isolation` too. The table is
readable across tenants only through `job_tenants_page`: its `owner_list` policy is granted
`TO CURRENT_USER`, the role running this migration, which owns that definer function, exactly
as `owner_drain` is for invitations (0059). The runtime role holds no privilege on the table.

A tenant's scheduled work is attributed to its scheduler principal, kind `SYSTEM`, which
`scheduler_actor` creates on first use. Its id is derived from the tenant,
`md5('execbound.scheduler:' || tenant_id)::uuid`, and `principals_system_id` holds that id to
kind `SYSTEM` and kind `SYSTEM` to that id. So `principal_guard` recognises it by
comparing ids, without reading `principals`: it refuses the scheduler principal in every
column through which a principal authenticates or gains authority (`GUARDED`, which
`execbound.principal_columns` classifies with every other principal column), under any fence
and for any role. `principals_system_frozen` refuses any change to it, `access_effective_kind`
answers `SYSTEM` for it and `access_has_permission` false. `assistant_turn_retire_due` retires
thirty-day-old assistant text with no actor, and `agents_sleep` no longer counts the
scheduler's events as activity. Neither new definer function takes a time from its caller.

Design: docs/superpowers/specs/2026-09-26-scheduled-jobs-every-workspace-design.md.
"""

from alembic import op
from sqlalchemy import text

revision = "0064_scheduled_jobs"
down_revision = "0063_personal_access_tokens"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
SUPABASE_ROLES = ("anon", "authenticated", "service_role")
KINDS = "('AGENT', 'HUMAN_APPROVER', 'ADMIN')"
KINDS_WITH_SYSTEM = "('AGENT', 'HUMAN_APPROVER', 'ADMIN', 'SYSTEM')"

DIRECTORY = """
CREATE TABLE execbound.job_tenants (
    tenant_id uuid PRIMARY KEY REFERENCES execbound.tenants(tenant_id) ON DELETE CASCADE,
    added_at timestamptz NOT NULL DEFAULT now()
)
"""

ENROLL = """
CREATE FUNCTION execbound.job_tenants_enroll() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO execbound.job_tenants(tenant_id) VALUES (NEW.tenant_id)
    ON CONFLICT (tenant_id) DO NOTHING;
    RETURN NEW;
END $$
"""

PAGE = """
CREATE FUNCTION execbound.job_tenants_page(p_after uuid, p_limit integer)
RETURNS TABLE(tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT j.tenant_id FROM execbound.job_tenants j
     WHERE (p_after IS NULL OR j.tenant_id > p_after) AND p_limit BETWEEN 1 AND 500
     ORDER BY j.tenant_id
     LIMIT p_limit
$$
"""

# Every column through which a principal authenticates or gains authority. The application's
# copy is `execbound.principal_columns.GUARDED`; tests/test_scheduled_jobs_schema.py holds the
# two equal and fails on any principal column classified in neither place.
GUARDED = (
    ("access_group_members", "principal_id"),
    ("access_principals", "principal_id"),
    ("access_role_grants", "principal_id"),
    ("account_factors", "principal_id"),
    ("account_passkeys", "principal_id"),
    ("account_requests", "principal_id"),
    ("agent_bindings", "principal_id"),
    ("approval_decisions", "principal_id"),
    ("approval_scopes", "approver_id"),
    ("approvals", "decided_by"),
    ("arcade_hooks", "principal_id"),
    ("credentials", "principal_id"),
    ("federated_sign_ins", "principal_id"),
    ("human_sessions", "principal_id"),
    ("identity_invitations", "principal_id"),
    ("identity_links", "principal_id"),
    ("monitor_agents", "linked_principal_id"),
    ("password_resets", "principal_id"),
    ("personal_access_tokens", "principal_id"),
    ("principal_group_members", "principal_id"),
    ("principal_identities", "principal_id"),
    ("principal_passwords", "principal_id"),
    ("principals", "replaced_by"),
    ("space_members", "principal_id"),
    ("user_factors", "pending_principal_id"),
    ("user_factors", "principal_id"),
    ("user_passkeys", "principal_id"),
    ("workspace_invitations", "accepted_principal_id"),
    ("workspace_memberships", "principal_id"),
)

# One invoker function for every guarded column, told the column by its trigger argument. It
# compares the column with the tenant's derived scheduler id and reads no table, so it holds
# under any fence (three guarded tables are fenced by account, not tenant) and for any role.
GUARD = """
CREATE FUNCTION execbound.principal_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (to_jsonb(NEW) ->> TG_ARGV[0])::uuid
       = md5('execbound.scheduler:' || NEW.tenant_id::text)::uuid THEN
        RAISE EXCEPTION 'SYSTEM_PRINCIPAL';
    END IF;
    RETURN NEW;
END $$
"""

FROZEN = """
CREATE FUNCTION execbound.principals_system_frozen() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.kind = 'SYSTEM' OR NEW.kind = 'SYSTEM' THEN
        RAISE EXCEPTION 'SYSTEM_PRINCIPAL';
    END IF;
    RETURN NEW;
END $$
"""

# Made on first use, under the caller's fence and the tenant lock the caller already holds.
# The id is derived, so two passes racing to make it insert the same row: one inserts, the
# other's `ON CONFLICT DO NOTHING` finds it. Number 1: every principal needs a number above
# zero (0058), and neither unique number index covers this kind, so no one's number moves.
SCHEDULER = """
CREATE FUNCTION execbound.scheduler_actor() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid;
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    v_principal := md5('execbound.scheduler:' || v_tenant::text)::uuid;
    INSERT INTO execbound.principals(tenant_id, principal_id, kind, label, number)
    VALUES (v_tenant, v_principal, 'SYSTEM', 'ExecBound scheduler', 1)
    ON CONFLICT DO NOTHING;
    RETURN jsonb_build_object('principal_id', v_principal, 'created', FOUND);
END $$
"""

RETIRE_DUE = """
CREATE FUNCTION execbound.assistant_turn_retire_due() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_count integer;
BEGIN
    -- 0047's prologue, which `assistant_turn_retire` opens with: the tenant control lock every
    -- administration function takes, so retirement serialises with them, and taken before the
    -- checks so they read the tenant under it. It is skipped when no fenced, active tenant
    -- exists (an unfenced call writes no control row), and the checks below then refuse.
    IF v_tenant IS NOT NULL AND EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at)
        VALUES (v_tenant, now()) ON CONFLICT (tenant_id) DO NOTHING;
        PERFORM 1 FROM execbound.tenant_policy_control WHERE tenant_id = v_tenant FOR UPDATE;
    END IF;
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.assistant_turns
       SET question = NULL, steps = '[]'::jsonb, answer = NULL, cited_ids = '[]'::jsonb,
           retired_at = now()
     WHERE tenant_id = v_tenant AND retired_at IS NULL AND completed_at IS NOT NULL
       AND completed_at <= now() - interval '30 days';
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$
"""

# The access functions stop treating an unknown kind as a person: `access_effective_kind`
# answered HUMAN_APPROVER for any kind but AGENT and ADMIN. Dormancy measures a workspace's
# last execution event, and the scheduler's are not activity.
PATCHES = (
    (
        "access_has_permission",
        "IF v_kind IS NULL OR v_kind='AGENT' THEN RETURN false; END IF;",
        "IF v_kind IS NULL OR v_kind IN ('AGENT','SYSTEM') THEN RETURN false; END IF;",
    ),
    (
        "access_effective_kind",
        "SELECT CASE WHEN p.kind='AGENT' THEN 'AGENT'",
        "SELECT CASE WHEN p.kind IN ('AGENT','SYSTEM') THEN p.kind",
    ),
    (
        "agents_sleep",
        "WHERE e.tenant_id = v_tenant AND e.kind LIKE 'execution.%';",
        "WHERE e.tenant_id = v_tenant AND e.kind LIKE 'execution.%'\n"
        "       AND NOT EXISTS (SELECT 1 FROM execbound.principals s\n"
        "                        WHERE s.tenant_id = e.tenant_id AND s.principal_id = e.actor_id\n"
        "                          AND s.kind = 'SYSTEM');",
    ),
)

# The definer functions this revision adds, each granted to the runtime role and nothing else.
SIGNATURES = (
    "job_tenants_page(uuid, integer)",
    "scheduler_actor()",
    "assistant_turn_retire_due()",
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _replace(function: str, before: str, after: str) -> None:
    """0061's patch: the fragment must be in the live definition exactly once, or it is refused."""
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = :name"
        ),
        {"name": function},
    ).scalar_one()
    if definition.count(before) != 1:
        raise RuntimeError(f"{function} no longer has the fragment 0064 patches")
    # CREATE OR REPLACE keeps the owner, SECURITY DEFINER and the grants. Straight to the
    # driver with every percent sign doubled, as 0061 does.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def _directory() -> None:
    # The strongest locks first, as 0062 takes them: lifting FORCE and changing constraints
    # take ACCESS EXCLUSIVE anyway, and holding them from the start means no tenant is created
    # between the backfill and the trigger that enrols the next one.
    op.execute("LOCK TABLE execbound.tenants IN ACCESS EXCLUSIVE MODE")
    op.execute("LOCK TABLE execbound.principals IN ACCESS EXCLUSIVE MODE")
    op.execute(DIRECTORY)
    # An owner that does not bypass row security reads every tenant only with FORCE lifted;
    # `row_security = off` makes a policy that still applied raise rather than read less. Row
    # security on the new table comes after the backfill, so the insert is not filtered either.
    op.execute("ALTER TABLE execbound.tenants NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    op.execute(
        "INSERT INTO execbound.job_tenants(tenant_id) SELECT tenant_id FROM execbound.tenants"
    )
    op.execute("ALTER TABLE execbound.tenants FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.job_tenants ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.job_tenants FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON execbound.job_tenants "
        f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
    )
    # The directory's cross-tenant read. Granted to the role running this migration, which
    # owns `job_tenants_page`; the runtime role never matches it.
    op.execute(
        "CREATE POLICY owner_list ON execbound.job_tenants FOR SELECT TO CURRENT_USER USING (true)"
    )
    op.execute("REVOKE ALL ON execbound.job_tenants FROM PUBLIC, execbound_app")
    for role in SUPABASE_ROLES:
        if role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.job_tenants FROM {role}")
    op.execute(ENROLL)
    op.execute("REVOKE ALL ON FUNCTION execbound.job_tenants_enroll() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER tenants_enroll AFTER INSERT ON execbound.tenants "
        "FOR EACH ROW EXECUTE FUNCTION execbound.job_tenants_enroll()"
    )
    op.execute(PAGE)


def _scheduler() -> None:
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_kind_check")
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_kind_check "
        f"CHECK (kind IN {KINDS_WITH_SYSTEM})"
    )
    # Kind SYSTEM and the derived id go together, both ways. `principal_guard` recognises the
    # scheduler principal only by its id, so a SYSTEM principal under any other id would pass
    # every guard; and `scheduler_actor`'s `ON CONFLICT DO NOTHING` names no conflict target,
    # so a principal of another kind already holding the derived id would be returned as the
    # scheduler. With this, the derived id is the SYSTEM principal and nothing else.
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_system_id "
        "CHECK ((kind = 'SYSTEM') = "
        "(principal_id = md5('execbound.scheduler:' || tenant_id::text)::uuid))"
    )
    op.execute(
        "CREATE UNIQUE INDEX principals_system ON execbound.principals (tenant_id) "
        "WHERE kind = 'SYSTEM'"
    )
    op.execute(FROZEN)
    op.execute("REVOKE ALL ON FUNCTION execbound.principals_system_frozen() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER principals_system_frozen BEFORE UPDATE ON execbound.principals "
        "FOR EACH ROW EXECUTE FUNCTION execbound.principals_system_frozen()"
    )
    op.execute(GUARD)
    op.execute("REVOKE ALL ON FUNCTION execbound.principal_guard() FROM PUBLIC")
    for table, column in GUARDED:
        op.execute(
            f"CREATE TRIGGER system_guard_{column} BEFORE INSERT OR UPDATE OF {column} "
            f"ON execbound.{table} FOR EACH ROW "
            f"EXECUTE FUNCTION execbound.principal_guard('{column}')"
        )
    for function, before, after in PATCHES:
        _replace(function, before, after)
    op.execute(SCHEDULER)
    op.execute(RETIRE_DUE)


def upgrade() -> None:
    _directory()
    _scheduler()
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in SUPABASE_ROLES:
            if role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    # The upgrade's locks, in its order and before anything else, as 0062's downgrade takes
    # its lock. Without them the downgrade would hold `principals` from its first statement
    # and reach `tenants` only at its end, so a live transaction that had written a tenant
    # and went on to write a principal would deadlock with it. Taken first, it waits its turn.
    op.execute("LOCK TABLE execbound.tenants IN ACCESS EXCLUSIVE MODE")
    op.execute("LOCK TABLE execbound.principals IN ACCESS EXCLUSIVE MODE")
    # The audit chain names the scheduler principals, so they cannot be dropped; an owner that
    # does not bypass row security sees none unfenced, so FORCE is lifted around the count.
    op.execute("ALTER TABLE execbound.principals NO FORCE ROW LEVEL SECURITY")
    retained = (
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM execbound.principals WHERE kind = 'SYSTEM')"))
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.principals FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "Scheduler principals require a verified full restore; lossy downgrade refused"
        )
    op.execute("DROP FUNCTION execbound.assistant_turn_retire_due()")
    op.execute("DROP FUNCTION execbound.scheduler_actor()")
    for function, before, after in reversed(PATCHES):
        _replace(function, after, before)
    for table, column in GUARDED:
        op.execute(f"DROP TRIGGER system_guard_{column} ON execbound.{table}")
    op.execute("DROP FUNCTION execbound.principal_guard()")
    op.execute("DROP TRIGGER principals_system_frozen ON execbound.principals")
    op.execute("DROP FUNCTION execbound.principals_system_frozen()")
    op.execute("DROP INDEX execbound.principals_system")
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_system_id")
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_kind_check")
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_kind_check "
        f"CHECK (kind IN {KINDS})"
    )
    # The directory holds nothing that is not derived from `tenants`, so it is dropped outright.
    op.execute("DROP TRIGGER tenants_enroll ON execbound.tenants")
    op.execute("DROP FUNCTION execbound.job_tenants_enroll()")
    op.execute("DROP FUNCTION execbound.job_tenants_page(uuid, integer)")
    op.execute("DROP TABLE execbound.job_tenants")
