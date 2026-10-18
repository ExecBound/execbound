# SPDX-License-Identifier: AGPL-3.0-only
"""An administrator narrowed to spaces administers those spaces' agents and people alone.

An agent is owned by one space, and a person who holds any membership has no authority outside
their spaces (the spaces design, refinement 3b). `0071_space_credential_scope` gave the three
credential functions the check `admin_create_principal` and `admin_assign_approver` make, and
left two gaps its pull request reported (#675):

1. Every other function that acts on an agent by id never asked. A narrowed administrator
   labelled, deactivated, reactivated, bound and unbound another space's agent, and withdrew
   another space's approver scope or took it over by assigning the same approver, target and
   action in their own space.
2. A person belongs to no space, so 0071 left a person outside the check, and a narrowed
   administrator could issue a credential, mint a set-password code, change the sign-in
   address, invite or link a directory account for a person seated only in another space.
   Each of those signs in as the person, with the person's approver authority there.

On 8 October 2026 it was decided that people are scoped to the administrator's spaces.
For an actor without workspace-wide `access.manage` who holds any membership, a write on a
person is allowed only when the person holds at least one membership and every space they are
seated in is one where the actor's membership is `ADMIN`, so the person's whole reach lies
inside the actor's administration. A person with no membership has workspace-wide reach and
is refused. So is a person whose reach comes from the access model, which only a workspace
administrator changes: a managed person, whose roles rather than seats are their reach, and a
member of an access group, whose grants reach its members. The memberships are read from
`space_members` in the statement that acts, never from an argument. A workspace administrator
is unchanged.

Each refusal is the code the function already gives a target that does not exist, so it tells
the caller nothing a nonexistent target would not. The one exception is the approver scope a
narrowed administrator would take over: `admin_assign_approver` already answers `INVALID_SPACE`
for a space that is not theirs, and answers it here too.

The functions are patched in place, as 0071 patched its three: the live definition is read,
each fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the signature,
owner, `SECURITY DEFINER`, `search_path` and grants. The downgrade restores each body byte for
byte.
"""

from alembic import op
from sqlalchemy import text

revision = "0072_space_principal_scope"
down_revision = "0071_space_credential_scope"
branch_labels = None
depends_on = None

# The person half of the rule, read against `p`, the target principal's row. A person is
# administered by a narrowed administrator only when every seat is in one of their ADMIN
# spaces, there is at least one seat, and no role from the access model reaches them.
PERSON = """EXISTS (
               SELECT 1 FROM execbound.space_members ts
               WHERE ts.tenant_id = v_tenant AND ts.principal_id = p.principal_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM execbound.space_members ts
               WHERE ts.tenant_id = v_tenant AND ts.principal_id = p.principal_id
                 AND NOT EXISTS (
                     SELECT 1 FROM execbound.space_members am
                     WHERE am.tenant_id = v_tenant AND am.principal_id = p_actor
                       AND am.space_id = ts.space_id AND am.role = 'ADMIN'
                 )
           )
           AND NOT EXISTS (
               SELECT 1 FROM execbound.access_principals ap
               WHERE ap.tenant_id = v_tenant AND ap.principal_id = p.principal_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM execbound.access_group_members gm
               WHERE gm.tenant_id = v_tenant AND gm.principal_id = p.principal_id
           )"""

# 0071's agent check, unchanged, with the person half in place of "a person passes".
MAY_ADMINISTER = (
    """((p.space_id IS NULL
            AND """
    + PERSON
    + """)
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
)


def may_administer_space(column: str) -> str:
    """The narrowing `admin_create_principal` applies, against a row's own space column."""
    return (
        """(execbound.access_has_permission(p_actor,'access.manage',NULL,false)
           OR NOT EXISTS (
               SELECT 1 FROM execbound.space_members m
               WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
           )
           OR EXISTS (
               SELECT 1 FROM execbound.space_members m
               WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
                 AND m.space_id = """
        + column
        + """ AND m.role = 'ADMIN'
           ))"""
    )


def principal_guard(comment: str) -> str:
    """Refuse `p_principal` with `INVALID_PRINCIPAL` unless the actor may administer it."""
    return (
        "    -- "
        + comment
        + """ (0072).
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
    )


def principal_exists(column: str) -> str:
    """True when the actor may administer the principal a row's column names."""
    return (
        """EXISTS (
           SELECT 1 FROM execbound.principals p
           WHERE p.tenant_id = v_tenant AND p.principal_id = """
        + column
        + """
             AND """
        + MAY_ADMINISTER
        + """
       )"""
    )


def discovered_exists(column: str) -> str:
    """True when the actor may administer the space of the connection that lists an agent."""
    return (
        """EXISTS (
           SELECT 1 FROM execbound.monitor_agents a
           JOIN execbound.monitor_connections k
             ON k.tenant_id = a.tenant_id AND k.connection_id = a.connection_id
           WHERE a.tenant_id = v_tenant AND a.agent_id = """
        + column
        + """
             AND """
        + may_administer_space("k.space_id")
        + """
       )"""
    )


def before(anchor: str, inserted: str) -> tuple[str, str]:
    return anchor, inserted + anchor


def after(anchor: str, inserted: str) -> tuple[str, str]:
    return anchor, anchor + inserted


# The three credential functions keep 0071's check and lose its "a person passes".
PERSON_PASSES = "(p.space_id IS NULL\n           OR execbound.access_has_permission"
PERSON_CHECKED = (
    "((p.space_id IS NULL\n"
    "            -- A person whose every seat is in one of their ADMIN spaces (0072).\n"
    "            AND " + PERSON + ")\n           OR execbound.access_has_permission"
)

# A person's sign-in: an address, a set-password code, a directory invitation and a link.
SIGN_IN_TARGET = (
    "          AND p.kind = 'HUMAN_APPROVER' AND "
    "execbound.access_effective_kind(p.principal_id) <> 'ADMIN'\n"
    "    ) THEN\n"
    "        RAISE EXCEPTION 'INVALID_PRINCIPAL';"
)
SIGN_IN_CHECKED = (
    "          AND p.kind = 'HUMAN_APPROVER' AND "
    "execbound.access_effective_kind(p.principal_id) <> 'ADMIN'\n"
    "          -- An administrator narrowed to spaces signs in their spaces' people alone "
    "(0072).\n"
    "          AND " + MAY_ADMINISTER + "\n"
    "    ) THEN\n"
    "        RAISE EXCEPTION 'INVALID_PRINCIPAL';"
)

UNBIND_WHERE = "    WHERE tenant_id = v_tenant AND binding_id = p_binding AND unbound_at IS NULL\n"
INVITATION_WHERE = "       AND redeemed_at IS NULL AND revoked_at IS NULL\n"
INVITATION_RETURNING = "    RETURNING principal_id INTO v_principal;\n"
TOKEN_WHERE = "       AND revoked_at IS NULL AND deleted_at IS NULL\n"
TOKEN_RETURNING = "    RETURNING credential_id INTO v_credential;\n"
DELETE_TOKEN_WHERE = (
    "     WHERE k.tenant_id = v_tenant AND k.token_id = p_token AND k.deleted_at IS NULL\n"
)
UNASSIGN_WHERE = "      AND canonical_target_id = p_target AND action = p_action AND active;\n"

PATCHES: dict[str, tuple[tuple[str, str], ...]] = {
    "admin_issue_credential": ((PERSON_PASSES, PERSON_CHECKED),),
    "admin_revoke_credential": ((PERSON_PASSES, PERSON_CHECKED),),
    "admin_delete_credential": ((PERSON_PASSES, PERSON_CHECKED),),
    "admin_label_principal": (
        before(
            "    UPDATE execbound.principals SET label = v_label\n",
            principal_guard("An administrator narrowed to spaces labels their own alone"),
        ),
    ),
    "admin_deactivate_principal": (
        before(
            "    UPDATE execbound.principals SET active = false, deactivated_at = v_now\n",
            principal_guard("An administrator narrowed to spaces deactivates their own alone"),
        ),
    ),
    "admin_reactivate_principal": (
        before(
            "    SELECT p.kind, p.deactivated_at INTO v_kind, v_deactivated\n",
            principal_guard("An administrator narrowed to spaces reactivates their own alone"),
        ),
    ),
    "admin_bind_agent": (
        before(
            "    PERFORM 1 FROM execbound.monitor_agents a\n",
            principal_guard("An administrator narrowed to spaces binds their agents alone"),
        ),
        after(
            "    IF p_agent IS NULL OR NOT FOUND THEN\n"
            "        RAISE EXCEPTION 'INVALID_AGENT';\n"
            "    END IF;\n",
            "    -- ... and to agents their own spaces' connections list (0072).\n"
            "    IF NOT " + discovered_exists("p_agent") + " THEN\n"
            "        RAISE EXCEPTION 'INVALID_AGENT';\n"
            "    END IF;\n",
        ),
    ),
    "admin_unbind_agent": (
        after(
            UNBIND_WHERE,
            "      -- An administrator narrowed to spaces unbinds their own alone (0072).\n"
            "      AND " + principal_exists("agent_bindings.principal_id") + "\n"
            "      AND " + discovered_exists("agent_bindings.agent_id") + "\n",
        ),
    ),
    "admin_set_email": ((SIGN_IN_TARGET, SIGN_IN_CHECKED),),
    "admin_reset_password": ((SIGN_IN_TARGET, SIGN_IN_CHECKED),),
    "directory_invite": ((SIGN_IN_TARGET, SIGN_IN_CHECKED),),
    "directory_link": ((SIGN_IN_TARGET, SIGN_IN_CHECKED),),
    "directory_unlink": ((SIGN_IN_TARGET, SIGN_IN_CHECKED),),
    "directory_invitation_revoke": (
        (
            INVITATION_WHERE + INVITATION_RETURNING,
            INVITATION_WHERE
            + "       -- An administrator narrowed to spaces revokes their people's alone (0072).\n"
            "       AND "
            + principal_exists("identity_invitations.principal_id")
            + "\n"
            + INVITATION_RETURNING,
        ),
    ),
    "admin_revoke_personal_token": (
        (
            TOKEN_WHERE + TOKEN_RETURNING,
            TOKEN_WHERE + "       -- A token is its owner's, and their administrator's (0072).\n"
            "       AND (personal_access_tokens.principal_id = p_actor\n"
            "            OR "
            + principal_exists("personal_access_tokens.principal_id")
            + ")\n"
            + TOKEN_RETURNING,
        ),
    ),
    "admin_delete_personal_token": (
        after(
            DELETE_TOKEN_WHERE,
            "       -- A token is its owner's, and their administrator's (0072).\n"
            "       AND (k.principal_id = p_actor OR " + principal_exists("k.principal_id") + ")\n",
        ),
    ),
    "admin_unassign_approver": (
        (
            UNASSIGN_WHERE,
            UNASSIGN_WHERE[:-2]
            + "\n      -- An administrator narrowed to spaces withdraws their spaces' scopes "
            "alone (0072).\n"
            "      AND " + may_administer_space("approval_scopes.space_id") + ";\n",
        ),
    ),
    "admin_assign_approver": (
        before(
            "    BEGIN\n        INSERT INTO execbound.approval_scopes\n",
            "    -- One approver, target and action is one row in one space: an administrator\n"
            "    -- narrowed to spaces takes no other space's live scope into theirs (0072).\n"
            "    IF EXISTS (\n"
            "        SELECT 1 FROM execbound.approval_scopes e\n"
            "        WHERE e.tenant_id = v_tenant AND e.approver_id = p_approver\n"
            "          AND e.canonical_target_id = p_target AND e.action = p_action AND e.active\n"
            "          AND NOT " + may_administer_space("e.space_id") + "\n"
            "    ) THEN\n"
            "        RAISE EXCEPTION 'INVALID_SPACE';\n"
            "    END IF;\n",
        ),
    ),
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
