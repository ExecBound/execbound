# SPDX-License-Identifier: AGPL-3.0-only
"""Only a workspace administrator sets the organization's MFA requirement.

The requirement (`account_security_policy`) decides for every person of the tenant whether
they must enrol a second factor: `all`, `admins` or `optional`. The `policy` operation of
`account_security_change` and `user_security_change` asked only that the session's kind be
`ADMIN` and its factor fresh, which an administrator narrowed to spaces satisfies, so an
administrator seated as `ADMIN` in one space could lower the whole workspace's requirement to
`optional` (#680 reported it).

On 8 October 2026 it was decided that the workspace-wide settings take workspace
administrators alone. Each function now asks, after its existing check, what `space_create`
and the other workspace-wide functions ask, in the same words with this function's own names
for the actor and the tenant: an actor without workspace-wide `access.manage` who holds any
membership is refused, with the code the operation already gives an actor who is not an
administrator (`RECENT_AUTH_REQUIRED`). The other settings of this decision (the mode, the
approval deadline, the emergency stop and the assistant switch) are Python store functions and
are restricted there.

The functions are patched in place, as 0071 to 0073 patched theirs: the live definition is
read, each fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the signature,
owner, `SECURITY DEFINER`, `search_path` and grants. The downgrade restores each body byte for
byte.
"""

from alembic import op
from sqlalchemy import text

revision = "0074_workspace_settings_admin"
down_revision = "0073_directory_workspace_admin"
branch_labels = None
depends_on = None

# An administrator narrowed to spaces, in the words `space_create` uses since
# `0047_access_control` and 0071 to 0073 repeat: no workspace-wide `access.manage`, and a
# membership of any space. These two functions name the actor `s.principal_id`, from the
# session, and the tenant `t`.
NARROWED = """NOT execbound.access_has_permission(s.principal_id,'access.manage',NULL,false)
            AND EXISTS (
                SELECT 1 FROM execbound.space_members m
                WHERE m.tenant_id = t AND m.principal_id = s.principal_id
            )"""

# The requirement's own check in both functions, word for word.
POLICY_CHECK = (
    "    ELSIF p_operation='policy' THEN\n"
    "        IF s.kind<>'ADMIN' OR NOT fresh THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; "
    "END IF;\n"
)
WORKSPACE_ONLY = (
    POLICY_CHECK
    + "        -- The requirement is the whole workspace's, so an administrator narrowed to\n"
    "        -- spaces sets none of it (0074).\n"
    "        IF " + NARROWED + " THEN\n"
    "            RAISE EXCEPTION 'RECENT_AUTH_REQUIRED';\n"
    "        END IF;\n"
)

PATCHES: dict[str, tuple[tuple[str, str], ...]] = {
    "account_security_change": ((POLICY_CHECK, WORKSPACE_ONLY),),
    "user_security_change": ((POLICY_CHECK, WORKSPACE_ONLY),),
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
    for old, new in pairs:
        # A definition that no longer carries the fragment exactly once was changed by
        # something this migration does not know, and is refused rather than guessed at.
        if definition.count(old) != 1:
            raise RuntimeError(f"{name} no longer has a fragment {revision} patches")
        definition = definition.replace(old, new)
    # Straight to the driver, every percent sign doubled: psycopg reads `%` as a placeholder.
    conn.exec_driver_sql(definition.replace("%", "%%"))


def upgrade() -> None:
    for name, pairs in PATCHES.items():
        _replace(name, pairs)


def downgrade() -> None:
    for name, pairs in PATCHES.items():
        _replace(name, tuple((new, old) for old, new in reversed(pairs)))
