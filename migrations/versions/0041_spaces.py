"""Spaces: separation of ownership and view inside one tenant.

A tenant gains spaces. A space is **a column plus a membership check in the store
functions, never a second fence**: every `tenant_isolation` policy here is unchanged and
forced, no policy reads a space setting, and the tenant stays the one security boundary
(design, decision 2).

Three tables are added. `spaces` and `space_members` are written by definer functions
alone, so the runtime holds `SELECT` on them and nothing else; `space_policy_selection`
is the one exception, because activation is already a fenced store function with an
audited ADMIN check and this design moves no authority, only a dimension.

The selection moves off `tenant_policy_control`: `active_bundle_id` and its `changed_at`
are dropped with the runtime's grant on them, and the partial "one ACTIVE bundle per
tenant" index goes with them, because the selection table's primary key is what gives at
most one selection per space. `ACTIVE` then means "selected by at least one space".

Every existing tenant is given exactly one space named `Default`, so every backfilled
column has an unambiguous value and nothing changes for a tenant that never creates a
second one. Existing `HUMAN_APPROVER` principals become members of it; existing `ADMIN`
principals get **no** membership, which is what makes them tenant administrators
(refinement 3b), so nothing an administrator can do today becomes unreachable when a
second space appears.

The downgrade refuses while any tenant holds more than one space, because merging would
be a decision about which customer's objects become whose.

Design: docs/superpowers/specs/2026-09-20-spaces-design.md
Plan: docs/superpowers/plans/2026-09-20-spaces.md
"""

from alembic import op
from sqlalchemy import text

revision = "0041_spaces"
down_revision = "0040_sign_in"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
ROLES = "('ADMIN', 'HUMAN_APPROVER')"

# Every table that gains a space column, with what the column is and how it is backfilled.
# `tests/test_spaces_isolation.py` reads this list, so a space-carrying table added later
# cannot be added without an isolation case (ruling 12).
OWNED_TABLES = (
    "connector_accounts",
    "policy_bundle_contents",
    "approval_scopes",
    "executions",
    "approvals",
    "execution_impact",
    "monitor_sources",
    "monitor_connections",
    "monitor_observations",
    "monitor_findings",
)
# The two that gain a column which is not ownership: a principal's space is null for a
# human, and a session's current space is a view and may be null for "All spaces".
OPTIONAL_COLUMNS = ("principals", "audit_events", "human_sessions")
# Which of the owned tables may also be offered tenant-wide (refinement 4a).
OFFERABLE = ("connector_accounts", "policy_bundle_contents")
# The covering index each owned table gains, leading (tenant_id, space_id, ...).
COVERING = {
    "connector_accounts": "(tenant_id, space_id, account_id)",
    "policy_bundle_contents": "(tenant_id, space_id, bundle_id)",
    "approval_scopes": "(tenant_id, space_id, approver_id)",
    "executions": "(tenant_id, space_id, created_at, execution_id)",
    "approvals": "(tenant_id, space_id, execution_id)",
    "execution_impact": "(tenant_id, space_id, action, state, confirmed_at)",
    "monitor_sources": "(tenant_id, space_id, source_id)",
    "monitor_connections": "(tenant_id, space_id, kind)",
    "monitor_observations": "(tenant_id, space_id, received_at, observation_id)",
    "monitor_findings": "(tenant_id, space_id, finding_id)",
}

SIGNATURES = (
    "space_create(text, text, uuid)",
    "space_rename(uuid, text, text, uuid)",
    "space_archive(uuid, uuid)",
    "space_unarchive(uuid, uuid)",
    "space_assign(uuid, uuid, text, uuid)",
    "space_unassign(uuid, uuid, uuid)",
    "session_set_space(uuid, uuid)",
)

# The 0021 preamble, restated: the tenant comes from the fence setting; the actor must be
# an active ADMIN of that active tenant. A space administration act is a **tenant**
# administrator's, which is an active ADMIN principal holding no membership at all
# (refinement 3b), so the preamble carries that second clause here.
ACTOR_CHECK = """
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

# A name is stored trimmed, so padding cannot mint a lookalike, and is free
# case-insensitively within the tenant.
NAME_CHECK = """
    IF v_name IS NULL OR char_length(v_name) NOT BETWEEN 1 AND 80
       OR (p_detail IS NOT NULL AND char_length(v_detail) NOT BETWEEN 1 AND 160) THEN
        RAISE EXCEPTION 'INVALID_NAME';
    END IF;
"""

SPACE_CHECK = """
    IF p_space IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND s.space_id = p_space
    ) THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
"""

CREATE = f"""
CREATE FUNCTION execbound.space_create(p_name text, p_detail text, p_actor uuid)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_space uuid := gen_random_uuid();
    v_name text := btrim(coalesce(p_name, ''));
    v_detail text := nullif(btrim(coalesce(p_detail, '')), '');
BEGIN
    {ACTOR_CHECK}
    {NAME_CHECK}
    IF EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND lower(s.name) = lower(v_name)
    ) THEN
        RAISE EXCEPTION 'NAME_TAKEN';
    END IF;
    INSERT INTO execbound.spaces
        (tenant_id, space_id, name, detail, created_at, created_by)
    VALUES (v_tenant, v_space, v_name, v_detail, now(), p_actor);
    RETURN v_space;
END $$
"""

RENAME = f"""
CREATE FUNCTION execbound.space_rename(
    p_space uuid, p_name text, p_detail text, p_actor uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_name text := btrim(coalesce(p_name, ''));
    v_detail text := nullif(btrim(coalesce(p_detail, '')), '');
BEGIN
    {ACTOR_CHECK}
    {SPACE_CHECK}
    {NAME_CHECK}
    IF EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND lower(s.name) = lower(v_name)
          AND s.space_id <> p_space
    ) THEN
        RAISE EXCEPTION 'NAME_TAKEN';
    END IF;
    UPDATE execbound.spaces SET name = v_name, detail = v_detail
     WHERE tenant_id = v_tenant AND space_id = p_space;
END $$
"""

# Archiving refuses the tenant's last unarchived space: a tenant with nowhere to admit
# work would be an emergency stop nobody chose, and the stop is the control for that.
ARCHIVE = f"""
CREATE FUNCTION execbound.space_archive(p_space uuid, p_actor uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_live integer;
BEGIN
    {ACTOR_CHECK}
    {SPACE_CHECK}
    -- Lock the tenant's spaces before counting them, so two archives cannot each read
    -- two live spaces and each leave the other's as the last one.
    PERFORM 1 FROM execbound.spaces s WHERE s.tenant_id = v_tenant FOR UPDATE;
    SELECT count(*) INTO v_live FROM execbound.spaces s
     WHERE s.tenant_id = v_tenant AND s.archived_at IS NULL;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND s.space_id = p_space AND s.archived_at IS NULL
    ) THEN
        RAISE EXCEPTION 'CONFLICT';
    END IF;
    IF v_live <= 1 THEN
        RAISE EXCEPTION 'CONFLICT';
    END IF;
    UPDATE execbound.spaces SET archived_at = now()
     WHERE tenant_id = v_tenant AND space_id = p_space;
END $$
"""

UNARCHIVE = f"""
CREATE FUNCTION execbound.space_unarchive(p_space uuid, p_actor uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    {SPACE_CHECK}
    IF NOT EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND s.space_id = p_space
          AND s.archived_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'CONFLICT';
    END IF;
    UPDATE execbound.spaces SET archived_at = NULL
     WHERE tenant_id = v_tenant AND space_id = p_space;
END $$
"""

# The space role narrows and only narrows (refinement 3a): a HUMAN_APPROVER principal may
# not hold the ADMIN role in a space, because every console guard reads `principals.kind`
# and a role that could raise it would weaken sixteen area modules at once. And the
# assignment that would leave the tenant with no tenant administrator is refused here,
# the way `revoke_executor_key` refuses a tenant's last live key.
ASSIGN = f"""
CREATE FUNCTION execbound.space_assign(
    p_space uuid, p_principal uuid, p_role text, p_actor uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
    v_admins integer;
BEGIN
    {ACTOR_CHECK}
    {SPACE_CHECK}
    IF EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND s.space_id = p_space
          AND s.archived_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'SPACE_ARCHIVED';
    END IF;
    SELECT p.kind INTO v_kind FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.active
       AND p.kind IN {ROLES};
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF p_role IS NULL OR p_role NOT IN {ROLES} THEN
        RAISE EXCEPTION 'INVALID_ROLE';
    END IF;
    IF p_role = 'ADMIN' AND v_kind <> 'ADMIN' THEN
        RAISE EXCEPTION 'INVALID_ROLE';
    END IF;
    -- A tenant administrator is an active ADMIN principal with no membership, so giving
    -- one their first membership narrows them. The tenant's ADMIN rows are locked before
    -- they are counted, so two assignments cannot each leave the other's as the last one.
    IF v_kind = 'ADMIN' AND NOT EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.principal_id = p_principal
    ) THEN
        PERFORM 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.kind = 'ADMIN' FOR UPDATE;
        SELECT count(*) INTO v_admins FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.active AND p.kind = 'ADMIN'
           AND NOT EXISTS (
               SELECT 1 FROM execbound.space_members m
               WHERE m.tenant_id = v_tenant AND m.principal_id = p.principal_id
           );
        IF v_admins <= 1 THEN
            RAISE EXCEPTION 'LAST_TENANT_ADMIN';
        END IF;
    END IF;
    INSERT INTO execbound.space_members
        (tenant_id, space_id, principal_id, role, assigned_at)
    VALUES (v_tenant, p_space, p_principal, p_role, now())
    ON CONFLICT (tenant_id, space_id, principal_id) DO UPDATE SET role = excluded.role;
END $$
"""

# Unassign is always allowed: removing a membership can only widen a person back toward
# tenant administration, never leave the tenant with none.
UNASSIGN = f"""
CREATE FUNCTION execbound.space_unassign(p_space uuid, p_principal uuid, p_actor uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    {SPACE_CHECK}
    DELETE FROM execbound.space_members
     WHERE tenant_id = v_tenant AND space_id = p_space AND principal_id = p_principal;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
END $$
"""

# A definer function rather than a runtime UPDATE grant, so "a session's current space is
# one of the person's spaces" is a database invariant rather than an application one. It
# is belt and braces: refinement 8b makes the read-time check the control.
SET_SPACE = """
CREATE FUNCTION execbound.session_set_space(p_session uuid, p_space uuid)
RETURNS void
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
    SELECT s.principal_id INTO v_principal FROM execbound.human_sessions s
     WHERE s.tenant_id = v_tenant AND s.session_id = p_session
       AND s.revoked_at IS NULL AND s.expires_at > now();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SESSION';
    END IF;
    IF p_space IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.space_id = p_space
          AND m.principal_id = v_principal
    ) AND NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = v_principal
          AND p.active AND p.kind = 'ADMIN'
          AND NOT EXISTS (
              SELECT 1 FROM execbound.space_members m
              WHERE m.tenant_id = v_tenant AND m.principal_id = v_principal
          )
          AND EXISTS (
              SELECT 1 FROM execbound.spaces s
              WHERE s.tenant_id = v_tenant AND s.space_id = p_space
          )
    ) THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    UPDATE execbound.human_sessions SET current_space_id = p_space
     WHERE tenant_id = v_tenant AND session_id = p_session;
END $$
"""

# `admin_create_principal` is dropped and recreated with a space, required exactly when
# the kind is AGENT: an agent is owned by a space, a human is a member of one.
CREATE_PRINCIPAL = """
CREATE FUNCTION execbound.admin_create_principal(
    p_actor uuid, p_kind text, p_space uuid)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid := gen_random_uuid();
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF p_kind IS NULL OR p_kind NOT IN ('AGENT', 'HUMAN_APPROVER') THEN
        RAISE EXCEPTION 'INVALID_KIND';
    END IF;
    -- An agent is owned by one space, so it must be given one. A person is a member of
    -- spaces rather than owned by one, and naming a space for them seats them in it with
    -- the role their kind allows, which is exactly what this migration does for every
    -- approver that already existed.
    IF p_kind = 'AGENT' AND p_space IS NULL THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    IF p_space IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM execbound.spaces s
            WHERE s.tenant_id = v_tenant AND s.space_id = p_space
        ) THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
        IF EXISTS (
            SELECT 1 FROM execbound.spaces s
            WHERE s.tenant_id = v_tenant AND s.space_id = p_space
              AND s.archived_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'SPACE_ARCHIVED';
        END IF;
        -- An administrator who is a member of spaces creates agents and seats people
        -- in those spaces only.
        IF EXISTS (
            SELECT 1 FROM execbound.space_members m
            WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
        ) AND NOT EXISTS (
            SELECT 1 FROM execbound.space_members m
            WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
              AND m.space_id = p_space AND m.role = 'ADMIN'
        ) THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
    END IF;
    INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id)
    VALUES (v_tenant, v_principal, p_kind,
            CASE WHEN p_kind = 'AGENT' THEN p_space END);
    IF p_kind = 'HUMAN_APPROVER' AND p_space IS NOT NULL THEN
        INSERT INTO execbound.space_members
            (tenant_id, space_id, principal_id, role, assigned_at)
        VALUES (v_tenant, p_space, v_principal, 'HUMAN_APPROVER', now());
    END IF;
    RETURN v_principal;
END $$
"""

# `approval_scopes` carries `space_id NOT NULL` (an approver may hold a scope in one space
# and not another), so the one function that inserts a scope has to say which space. This
# is the plan's amendment 14: the plan counted seven changed signatures and this is the
# eighth, because a NOT NULL column with no default cannot be written by a function that
# does not take it. `admin_unassign_approver` is unchanged: it deactivates a row by
# approver, target and action, and the row keeps the space it was created in.
ASSIGN_APPROVER = """
CREATE FUNCTION execbound.admin_assign_approver(
    p_actor uuid, p_approver uuid, p_target uuid, p_action text, p_space uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_approver
          AND p.active AND p.kind = 'HUMAN_APPROVER'
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.canonical_targets ct
        WHERE ct.tenant_id = v_tenant AND ct.canonical_target_id = p_target
    ) THEN
        RAISE EXCEPTION 'INVALID_TARGET';
    END IF;
    IF p_space IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND s.space_id = p_space
    ) THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    -- An administrator narrowed to spaces assigns scopes in those spaces only.
    IF EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
    ) AND NOT EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
          AND m.space_id = p_space AND m.role = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    BEGIN
        INSERT INTO execbound.approval_scopes
            (tenant_id, approver_id, canonical_target_id, action, active, space_id)
        VALUES (v_tenant, p_approver, p_target, p_action, true, p_space)
        ON CONFLICT (tenant_id, approver_id, canonical_target_id, action)
        DO UPDATE SET active = true, space_id = excluded.space_id;
    EXCEPTION WHEN check_violation OR not_null_violation THEN
        RAISE EXCEPTION 'INVALID_ACTION';
    END;
END $$
"""

OLD_ASSIGN_APPROVER = """
CREATE FUNCTION execbound.admin_assign_approver(
    p_actor uuid, p_approver uuid, p_target uuid, p_action text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_approver
          AND p.active AND p.kind = 'HUMAN_APPROVER'
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.canonical_targets ct
        WHERE ct.tenant_id = v_tenant AND ct.canonical_target_id = p_target
    ) THEN
        RAISE EXCEPTION 'INVALID_TARGET';
    END IF;
    BEGIN
        INSERT INTO execbound.approval_scopes
            (tenant_id, approver_id, canonical_target_id, action, active)
        VALUES (v_tenant, p_approver, p_target, p_action, true)
        ON CONFLICT (tenant_id, approver_id, canonical_target_id, action)
        DO UPDATE SET active = true;
    EXCEPTION WHEN check_violation OR not_null_violation THEN
        RAISE EXCEPTION 'INVALID_ACTION';
    END;
END $$
"""

OLD_CREATE_PRINCIPAL = """
CREATE FUNCTION execbound.admin_create_principal(p_actor uuid, p_kind text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid := gen_random_uuid();
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF p_kind IS NULL OR p_kind NOT IN ('AGENT', 'HUMAN_APPROVER') THEN
        RAISE EXCEPTION 'INVALID_KIND';
    END IF;
    INSERT INTO execbound.principals (tenant_id, principal_id, kind)
    VALUES (v_tenant, v_principal, p_kind);
    RETURN v_principal;
END $$
"""

FUNCTIONS = (CREATE, RENAME, ARCHIVE, UNARCHIVE, ASSIGN, UNASSIGN, SET_SPACE)


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _protect(table: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.{table}
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role", "execbound_app"):
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")


# Every table the data statements below read or write, in upgrade and in downgrade, and the
# two that gain a foreign key in between: adding one validates every existing row, and with
# row security off that validation raises on a table still forced rather than reading it.
BACKFILLED = (
    "tenants",
    "principals",
    "tenant_policy_control",
    *OWNED_TABLES,
    "audit_events",
    "human_sessions",
    "spaces",
    "space_members",
    "space_policy_selection",
)


def _unforced(tables: tuple[str, ...]) -> tuple[str, ...]:
    """Lift FORCE for the owner on the tables named, inside this migration's transaction.

    The data statements here read every tenant and write every tenant's rows as the owner,
    with no tenant fence. Where the owner bypasses row-level security (a local superuser,
    CI) that works as written. Where it does not, FORCE subjects the owner to
    `tenant_isolation`: every read finds nothing and every write touches nothing, silently.
    The hosted project's `execbound_owner` is neither superuser nor BYPASSRLS, and on
    20 September 2026 this migration created no space there and then failed
    `principals_space_kind_check` on the first AGENT row, rolling back whole.

    The pattern is 0007's: lock, lift FORCE, and turn row security off so that a statement
    it would still filter raises instead of quietly reading less. Only the tables that were
    forced are lifted, and `_forced` restores exactly those, so this can never force a
    table that was not. A rollback restores FORCE on any refusal.
    """
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"execbound.{table}" for table in tables)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    bind = op.get_bind()
    forced = tuple(
        table
        for table in tables
        if bind.execute(
            text("SELECT relforcerowsecurity FROM pg_class WHERE oid = to_regclass(:name)"),
            {"name": f"execbound.{table}"},
        ).scalar()
    )
    for table in forced:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    return forced


def _forced(tables: tuple[str, ...]) -> None:
    """Put back what `_unforced` lifted, before anything else in the migration runs."""
    op.execute("SET LOCAL row_security = on")
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")


def _grant(signature: str) -> None:
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role"):
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.spaces (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            space_id uuid NOT NULL,
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
            detail text CHECK (detail IS NULL OR char_length(detail) BETWEEN 1 AND 160),
            created_at timestamptz NOT NULL,
            created_by uuid NOT NULL,
            archived_at timestamptz CHECK (archived_at IS NULL OR archived_at >= created_at),
            PRIMARY KEY (tenant_id, space_id)
        )
    """)
    _protect("spaces")
    op.execute("CREATE UNIQUE INDEX spaces_name_lower ON execbound.spaces (tenant_id, lower(name))")
    op.execute("CREATE INDEX spaces_creator ON execbound.spaces (tenant_id, created_by)")
    op.execute(f"""
        CREATE TABLE execbound.space_members (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            space_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            role text NOT NULL CHECK (role IN {ROLES}),
            assigned_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, space_id, principal_id),
            FOREIGN KEY (tenant_id, space_id)
                REFERENCES execbound.spaces (tenant_id, space_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id)
        )
    """)
    _protect("space_members")
    # The visible set is read by person on every fenced read, so the person is the key.
    op.execute(
        "CREATE INDEX space_members_principal ON execbound.space_members "
        "(tenant_id, principal_id, space_id)"
    )
    op.execute("""
        CREATE TABLE execbound.space_policy_selection (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            space_id uuid NOT NULL,
            bundle_id uuid NOT NULL,
            changed_at timestamptz NOT NULL,
            changed_by uuid NOT NULL,
            PRIMARY KEY (tenant_id, space_id),
            FOREIGN KEY (tenant_id, space_id)
                REFERENCES execbound.spaces (tenant_id, space_id),
            FOREIGN KEY (tenant_id, bundle_id)
                REFERENCES execbound.policy_bundle_lifecycle (tenant_id, bundle_id)
        )
    """)
    _protect("space_policy_selection")
    op.execute(
        "CREATE INDEX space_policy_selection_bundle ON execbound.space_policy_selection "
        "(tenant_id, bundle_id)"
    )
    op.execute(
        "GRANT INSERT, UPDATE (bundle_id, changed_at, changed_by) "
        "ON execbound.space_policy_selection TO execbound_app"
    )
    # Everything from here to the policy selection reads and writes every tenant at once.
    lifted = _unforced(BACKFILLED)
    # One `Default` space per tenant, created by that tenant's earliest ADMIN principal.
    # `created_by` is NOT NULL and a tenant always has one, because nothing can be audited
    # before a tenant's first ADMIN exists; a tenant with none is given the zero principal
    # rather than skipped, so no tenant is left without a space.
    op.execute("""
        INSERT INTO execbound.spaces
            (tenant_id, space_id, name, detail, created_at, created_by)
        SELECT t.tenant_id, gen_random_uuid(), 'Default', NULL, now(),
               COALESCE(
                   (SELECT p.principal_id FROM execbound.principals p
                     WHERE p.tenant_id = t.tenant_id AND p.kind = 'ADMIN'
                     ORDER BY p.principal_id LIMIT 1),
                   '00000000-0000-0000-0000-000000000000'::uuid)
          FROM execbound.tenants t
    """)
    op.execute("ALTER TABLE execbound.principals ADD COLUMN space_id uuid")
    op.execute("""
        UPDATE execbound.principals p SET space_id = s.space_id
          FROM execbound.spaces s
         WHERE s.tenant_id = p.tenant_id AND p.kind = 'AGENT'
    """)
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_space_kind_check "
        "CHECK ((kind = 'AGENT') = (space_id IS NOT NULL))"
    )
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_space_fkey "
        "FOREIGN KEY (tenant_id, space_id) REFERENCES execbound.spaces (tenant_id, space_id)"
    )
    op.execute("CREATE INDEX principals_space ON execbound.principals (tenant_id, space_id)")
    for table in OWNED_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ADD COLUMN space_id uuid")
        op.execute(f"""
            UPDATE execbound.{table} o SET space_id = s.space_id
              FROM execbound.spaces s WHERE s.tenant_id = o.tenant_id
        """)
        op.execute(f"ALTER TABLE execbound.{table} ALTER COLUMN space_id SET NOT NULL")
        op.execute(
            f"ALTER TABLE execbound.{table} ADD CONSTRAINT {table}_space_fkey "
            "FOREIGN KEY (tenant_id, space_id) REFERENCES execbound.spaces (tenant_id, space_id)"
        )
        op.execute(f"CREATE INDEX {table}_space ON execbound.{table} {COVERING[table]}")
    for table in OFFERABLE:
        op.execute(
            f"ALTER TABLE execbound.{table} "
            "ADD COLUMN offered_tenant_wide boolean NOT NULL DEFAULT false"
        )
    # One active connection per tenant per kind becomes one per space per kind, which is
    # what lets an MSSP hold one Tines connection per customer.
    op.execute("DROP INDEX execbound.monitor_connections_one_active")
    op.execute(
        "CREATE UNIQUE INDEX monitor_connections_one_active ON execbound.monitor_connections "
        "(tenant_id, space_id, kind) WHERE active"
    )
    # A reader's filter only: never part of the hashed payload, so every retained event,
    # every head and every export stays byte-identical.
    op.execute("ALTER TABLE execbound.audit_events ADD COLUMN space_id uuid")
    op.execute(
        "ALTER TABLE execbound.audit_events ADD CONSTRAINT audit_events_space_fkey "
        "FOREIGN KEY (tenant_id, space_id) REFERENCES execbound.spaces (tenant_id, space_id)"
    )
    op.execute("CREATE INDEX audit_events_space ON execbound.audit_events (tenant_id, space_id)")
    # NULL means "All spaces"; this is a view and never ownership.
    op.execute("ALTER TABLE execbound.human_sessions ADD COLUMN current_space_id uuid")
    op.execute(
        "ALTER TABLE execbound.human_sessions ADD CONSTRAINT human_sessions_space_fkey "
        "FOREIGN KEY (tenant_id, current_space_id) "
        "REFERENCES execbound.spaces (tenant_id, space_id)"
    )
    op.execute(
        "CREATE INDEX human_sessions_space ON execbound.human_sessions "
        "(tenant_id, current_space_id)"
    )
    # Approvers become members of the default space; administrators deliberately do not,
    # so every existing administrator stays a tenant administrator (refinement 3b).
    op.execute("""
        INSERT INTO execbound.space_members
            (tenant_id, space_id, principal_id, role, assigned_at)
        SELECT p.tenant_id, s.space_id, p.principal_id, 'HUMAN_APPROVER', now()
          FROM execbound.principals p
          JOIN execbound.spaces s ON s.tenant_id = p.tenant_id
         WHERE p.kind = 'HUMAN_APPROVER'
    """)
    # The selection moves off the control row, with its grant and its index.
    op.execute("""
        INSERT INTO execbound.space_policy_selection
            (tenant_id, space_id, bundle_id, changed_at, changed_by)
        SELECT c.tenant_id, s.space_id, c.active_bundle_id,
               COALESCE(c.changed_at, now()),
               COALESCE(
                   (SELECT p.principal_id FROM execbound.principals p
                     WHERE p.tenant_id = c.tenant_id AND p.kind = 'ADMIN'
                     ORDER BY p.principal_id LIMIT 1),
                   '00000000-0000-0000-0000-000000000000'::uuid)
          FROM execbound.tenant_policy_control c
          JOIN execbound.spaces s ON s.tenant_id = c.tenant_id
         WHERE c.active_bundle_id IS NOT NULL
    """)
    _forced(lifted)
    op.execute("DROP INDEX execbound.tenant_policy_control_bundle")
    op.execute("DROP INDEX execbound.policy_bundle_one_active")
    op.execute("ALTER TABLE execbound.tenant_policy_control DROP COLUMN active_bundle_id")
    op.execute("REVOKE UPDATE ON execbound.tenant_policy_control FROM execbound_app")
    op.execute(
        "GRANT UPDATE (changed_at, stop_id, stopped_at, stopped_by, stop_reason, "
        "enforcement_mode, approval_deadline_seconds, assistant_enabled) "
        "ON execbound.tenant_policy_control TO execbound_app"
    )
    op.execute("DROP FUNCTION execbound.admin_create_principal(uuid, text)")
    op.execute(CREATE_PRINCIPAL)
    _grant("admin_create_principal(uuid, text, uuid)")
    op.execute("DROP FUNCTION execbound.admin_assign_approver(uuid, uuid, uuid, text)")
    op.execute(ASSIGN_APPROVER)
    _grant("admin_assign_approver(uuid, uuid, uuid, text, uuid)")
    for body in FUNCTIONS:
        op.execute(body)
    for signature in SIGNATURES:
        _grant(signature)


def downgrade() -> None:
    # Merging spaces would be a decision about which customer's objects become whose, and
    # deleting history to force a downgrade is not a recovery procedure. The count has to see
    # every tenant: under FORCE, an owner without BYPASSRLS would count none, pass the check
    # and then move no selection back, so the same lifting applies here as on the way up.
    # `policy_bundle_lifecycle` for the foreign key restored below, which validates its rows.
    lifted = _unforced(
        ("spaces", "space_policy_selection", "tenant_policy_control", "policy_bundle_lifecycle")
    )
    crowded = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM (SELECT tenant_id FROM execbound.spaces "
                "GROUP BY tenant_id HAVING count(*) > 1) AS many"
            )
        )
        .scalar_one()
    )
    if crowded:
        raise RuntimeError("Cannot downgrade while a tenant holds more than one space")
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP FUNCTION execbound.admin_create_principal(uuid, text, uuid)")
    op.execute(OLD_CREATE_PRINCIPAL)
    _grant("admin_create_principal(uuid, text)")
    op.execute("DROP FUNCTION execbound.admin_assign_approver(uuid, uuid, uuid, text, uuid)")
    op.execute(OLD_ASSIGN_APPROVER)
    _grant("admin_assign_approver(uuid, uuid, uuid, text)")
    op.execute("ALTER TABLE execbound.tenant_policy_control ADD COLUMN active_bundle_id uuid")
    op.execute(
        "ALTER TABLE execbound.tenant_policy_control ADD CONSTRAINT "
        "tenant_policy_control_tenant_id_active_bundle_id_fkey "
        "FOREIGN KEY (tenant_id, active_bundle_id) "
        "REFERENCES execbound.policy_bundle_lifecycle (tenant_id, bundle_id)"
    )
    op.execute("""
        UPDATE execbound.tenant_policy_control c SET active_bundle_id = s.bundle_id
          FROM execbound.space_policy_selection s WHERE s.tenant_id = c.tenant_id
    """)
    _forced(lifted)
    op.execute(
        "CREATE INDEX tenant_policy_control_bundle ON execbound.tenant_policy_control "
        "(tenant_id, active_bundle_id)"
    )
    op.execute(
        "CREATE UNIQUE INDEX policy_bundle_one_active ON execbound.policy_bundle_lifecycle "
        "(tenant_id) WHERE state = 'ACTIVE'"
    )
    op.execute("REVOKE UPDATE ON execbound.tenant_policy_control FROM execbound_app")
    op.execute(
        "GRANT UPDATE (active_bundle_id, changed_at, stop_id, stopped_at, stopped_by, "
        "stop_reason, enforcement_mode, approval_deadline_seconds, assistant_enabled) "
        "ON execbound.tenant_policy_control TO execbound_app"
    )
    op.execute("DROP INDEX execbound.human_sessions_space")
    op.execute("ALTER TABLE execbound.human_sessions DROP CONSTRAINT human_sessions_space_fkey")
    op.execute("ALTER TABLE execbound.human_sessions DROP COLUMN current_space_id")
    op.execute("DROP INDEX execbound.audit_events_space")
    op.execute("ALTER TABLE execbound.audit_events DROP CONSTRAINT audit_events_space_fkey")
    op.execute("ALTER TABLE execbound.audit_events DROP COLUMN space_id")
    op.execute("DROP INDEX execbound.monitor_connections_one_active")
    for table in OFFERABLE:
        op.execute(f"ALTER TABLE execbound.{table} DROP COLUMN offered_tenant_wide")
    for table in OWNED_TABLES:
        op.execute(f"DROP INDEX execbound.{table}_space")
        op.execute(f"ALTER TABLE execbound.{table} DROP CONSTRAINT {table}_space_fkey")
        op.execute(f"ALTER TABLE execbound.{table} DROP COLUMN space_id")
    op.execute(
        "CREATE UNIQUE INDEX monitor_connections_one_active ON execbound.monitor_connections "
        "(tenant_id, kind) WHERE active"
    )
    op.execute("DROP INDEX execbound.principals_space")
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_space_fkey")
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_space_kind_check")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN space_id")
    op.execute("DROP TABLE execbound.space_policy_selection")
    op.execute("DROP TABLE execbound.space_members")
    op.execute("DROP TABLE execbound.spaces")
