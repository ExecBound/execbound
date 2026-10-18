# SPDX-License-Identifier: AGPL-3.0-only
"""An administrator narrowed to spaces administers the keys of those spaces' agents alone.

An agent is owned by one space and its keys hang off its principal row, so a key acts in its
agent's space. An administrator who holds a membership is narrowed to their spaces (the spaces
design, refinement 3b): `admin_create_principal` and `admin_assign_approver` already let them
create agents and assign scopes only where their membership is `ADMIN`. The three credential
functions never asked. They checked that the actor was an effective administrator, which a
narrowed one still is through `access_has_permission`'s `p_any` branch, and that the target
was not one, so a narrowed administrator could issue a key for an agent of a space they do not
belong to, and revoke or delete that agent's keys (#662).

Each function now asks the question the other two ask, in the same words: an actor without
workspace-wide `access.manage` who holds any membership acts on an agent only where that
membership is `ADMIN`. The refusal is the code each function already gives a principal or a
credential the actor may not act on (`INVALID_PRINCIPAL` to issue; the update finds no row and
answers `INVALID_CREDENTIAL` to revoke and delete), so it tells the caller nothing a principal
or credential that does not exist would not. A person belongs to no space (`space_id` is null),
and a person's credential is administered exactly as before.

The functions are patched in place, as `0057_api_key_never` and `0070_first_password` patch
theirs: the live definition is read, each fragment must occur in it exactly once, and
`CREATE OR REPLACE` keeps the signature, owner, `SECURITY DEFINER`, `search_path` and grants.
The downgrade removes exactly what the upgrade added.
"""

from alembic import op
from sqlalchemy import text

revision = "0071_space_credential_scope"
down_revision = "0070_first_password"
branch_labels = None
depends_on = None

# The narrowing `admin_create_principal` and `admin_assign_approver` apply, read against the
# space of the principal the credential belongs to rather than a space the caller names. True
# when the actor may act on that principal: a person (no space), a workspace-wide administrator,
# an administrator with no membership, or one whose membership in the agent's space is ADMIN.
MAY_ADMINISTER = """(p.space_id IS NULL
           OR execbound.access_has_permission(p_actor,'access.manage',NULL,false)
           OR NOT EXISTS (
               SELECT 1 FROM execbound.space_members m
               WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
           )
           OR EXISTS (
               SELECT 1 FROM execbound.space_members m
               WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
                 AND m.space_id = p.space_id AND m.role = 'ADMIN'
           ))"""

# Inserted before the digest check, right after the check that refuses an administrator target,
# so a refused principal is refused before anything about the key is read.
ISSUE_BEFORE = "    IF p_credential IS NULL OR p_token_hash IS NULL"
ISSUE_AFTER = (
    """    -- An administrator narrowed to spaces issues keys for their agents alone (0071).
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
          AND """
    + MAY_ADMINISTER
    + """
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
"""
    + ISSUE_BEFORE
)

REVOKE_BEFORE = (
    "AND p.kind <> 'ADMIN' AND execbound.access_effective_kind(p.principal_id) <> 'ADMIN';\n"
)
REVOKE_AFTER = (
    "AND p.kind <> 'ADMIN' AND execbound.access_effective_kind(p.principal_id) <> 'ADMIN'\n"
    "      -- An administrator narrowed to spaces revokes their agents' keys alone (0071).\n"
    "      AND " + MAY_ADMINISTER + ";\n"
)

DELETE_BEFORE = "AND p.principal_id = c.principal_id AND p.kind = 'AGENT';\n"
DELETE_AFTER = (
    "AND p.principal_id = c.principal_id AND p.kind = 'AGENT'\n"
    "      -- An administrator narrowed to spaces deletes their agents' keys alone (0071).\n"
    "      AND " + MAY_ADMINISTER + ";\n"
)

PATCHES: dict[str, tuple[tuple[str, str], ...]] = {
    "admin_issue_credential": ((ISSUE_BEFORE, ISSUE_AFTER),),
    "admin_revoke_credential": ((REVOKE_BEFORE, REVOKE_AFTER),),
    "admin_delete_credential": ((DELETE_BEFORE, DELETE_AFTER),),
}


def _replace(name: str, pairs: tuple[tuple[str, str], ...]) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = :name"
        ),
        {"name": name},
    ).scalar_one()
    for before, after in pairs:
        # A definition that no longer carries the fragment exactly once was changed by
        # something this migration does not know, and is refused rather than guessed at.
        if definition.count(before) != 1:
            raise RuntimeError(f"{name} no longer has a fragment {revision} patches")
        definition = definition.replace(before, after)
    # Straight to the driver, every percent sign doubled: psycopg reads `%` as a placeholder.
    conn.exec_driver_sql(definition.replace("%", "%%"))


def upgrade() -> None:
    for name, pairs in PATCHES.items():
        _replace(name, pairs)


def downgrade() -> None:
    for name, pairs in PATCHES.items():
        _replace(name, tuple((after, before) for before, after in reversed(pairs)))
