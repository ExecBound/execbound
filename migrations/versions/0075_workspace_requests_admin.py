# SPDX-License-Identifier: AGPL-3.0-only
"""Only a workspace administrator records a response to a data or closure request.

The requests queue holds every person's requests, from every space: their data, the closure
of their account, and the closure of the workspace. The `resolve` operation of
`account_change` asked only that the session's kind be `ADMIN`, which an administrator narrowed
to spaces satisfies, so an administrator seated as `ADMIN` in one space could record a response
to anybody's request, a workspace closure included (#682 reported it).

On 8 October 2026 it was decided that the queue takes workspace administrators alone. The
operation now asks, after its existing check, what `space_create` and the other workspace-wide
functions ask, in the same words with this function's own names for the actor and the tenant:
an actor without workspace-wide `access.manage` who holds any membership is refused, with the
code the operation already gives an actor who is not an administrator (`FORBIDDEN`). Reading
the queue is a Python read under row-level security and is restricted there. A person's own
request, the `request` operation, is unchanged.

The function is patched in place, as 0071 to 0074 patched theirs: the live definition is read,
the fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the signature, owner,
`SECURITY DEFINER`, `search_path` and grants. The downgrade restores the body byte for byte.
"""

from alembic import op
from sqlalchemy import text

revision = "0075_workspace_requests_admin"
down_revision = "0074_workspace_settings_admin"
branch_labels = None
depends_on = None

# An administrator narrowed to spaces, in the words `space_create` uses since
# `0047_access_control` and 0071 to 0074 repeat: no workspace-wide `access.manage`, and a
# membership of any space. This function names the actor `s.principal_id`, from the session,
# and the tenant `t`.
NARROWED = """NOT execbound.access_has_permission(s.principal_id,'access.manage',NULL,false)
            AND EXISTS (
                SELECT 1 FROM execbound.space_members m
                WHERE m.tenant_id = t AND m.principal_id = s.principal_id
            )"""

# The response's own check, word for word.
RESOLVE_CHECK = (
    "        ELSIF p_operation='resolve' THEN\n"
    "          IF s.kind<>'ADMIN' OR p_data->>'state' NOT IN ('completed','declined')\n"
    "            THEN RAISE EXCEPTION 'FORBIDDEN'; END IF;\n"
)
WORKSPACE_ONLY = (
    RESOLVE_CHECK
    + "          -- The queue is the whole workspace's, so an administrator narrowed to\n"
    "          -- spaces answers none of it (0075).\n"
    "          IF " + NARROWED + " THEN\n"
    "            RAISE EXCEPTION 'FORBIDDEN';\n"
    "          END IF;\n"
)

PATCHES: dict[str, tuple[tuple[str, str], ...]] = {
    "account_change": ((RESOLVE_CHECK, WORKSPACE_ONLY),),
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
