# SPDX-License-Identifier: AGPL-3.0-only
"""Only a workspace administrator configures the tenant's own identity provider.

A provider signs people in to the whole tenant rather than to a space: registering an issuer
decides whose accounts can be linked, enabling it lets every linked account sign in, and
disabling it ends every directory session in the tenant at once. `directory_register` and
`directory_set_state` asked only that the actor be an effective administrator, which an
administrator narrowed to spaces still is through `access_has_permission`'s `p_any` branch, so
an administrator seated as `ADMIN` in one space registered, enabled and disabled the tenant's
provider (#677 reported it).

On 8 October 2026 it was decided that these take workspace administrators alone. Each asks
what `space_create` and the other workspace-wide functions ask, in the same words: an actor
without workspace-wide `access.manage` who holds any membership is refused, with the code an
actor who is not an administrator already gets (`INVALID_ACTOR`), before the provider is read,
so the refusal says nothing about it.

A sign-in through a provider that is not enabled is the test that verifies a registration,
and `directory_link_self` marked a draft verified for any active administrator or approver.
It now links through a draft or a verified provider for a workspace administrator alone and
answers anybody else `INVALID_PROVIDER`, the code `directory_store.link_self` already gave an
approver there. Linking one's own account through an enabled provider is unchanged.

The functions are patched in place, as 0071 and 0072 patched theirs: the live definition is
read, each fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the signature,
owner, `SECURITY DEFINER`, `search_path` and grants. The downgrade restores each body byte for
byte.
"""

from alembic import op
from sqlalchemy import text

revision = "0073_directory_workspace_admin"
down_revision = "0072_space_principal_scope"
branch_labels = None
depends_on = None

# An administrator narrowed to spaces, in the words `space_create` uses since
# `0047_access_control` and 0071 and 0072 repeat: no workspace-wide `access.manage`, and a
# membership of any space.
NARROWED = """NOT execbound.access_has_permission(p_actor,'access.manage',NULL,false) AND EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
    )"""

# The actor check both configuration functions open with, word for word.
ACTOR_CHECK = (
    "          AND p.active AND execbound.access_effective_kind(p_actor) = 'ADMIN'\n"
    "    ) THEN\n"
    "        RAISE EXCEPTION 'INVALID_ACTOR';\n"
    "    END IF;\n"
)
WORKSPACE_ONLY = (
    ACTOR_CHECK
    + "    -- The provider signs in the whole tenant, so an administrator narrowed to spaces\n"
    "    -- configures none of it (0073).\n"
    "    IF " + NARROWED + " THEN\n"
    "        RAISE EXCEPTION 'INVALID_ACTOR';\n"
    "    END IF;\n"
)

# The self-link reads the provider's state and refuses a disabled one; a provider that is not
# enabled is then linked through by a workspace administrator alone.
STATE_CHECK = (
    "    IF NOT FOUND OR v_state = 'disabled' THEN\n"
    "        RAISE EXCEPTION 'INVALID_PROVIDER';\n"
    "    END IF;\n"
)
TEST_SIGN_IN = (
    STATE_CHECK
    + "    -- A sign-in through a provider that is not enabled is the test that verifies it, and\n"
    "    -- only a workspace administrator configures the provider (0073).\n"
    "    IF v_state <> 'enabled' AND (\n"
    "        execbound.access_effective_kind(p_actor) <> 'ADMIN'\n"
    "        OR (" + NARROWED + ")\n"
    "    ) THEN\n"
    "        RAISE EXCEPTION 'INVALID_PROVIDER';\n"
    "    END IF;\n"
)

PATCHES: dict[str, tuple[tuple[str, str], ...]] = {
    "directory_register": ((ACTOR_CHECK, WORKSPACE_ONLY),),
    "directory_set_state": ((ACTOR_CHECK, WORKSPACE_ONLY),),
    "directory_link_self": ((STATE_CHECK, TEST_SIGN_IN),),
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
