# SPDX-License-Identifier: AGPL-3.0-only
"""An invitation may name the reviewer group its Approver joins on acceptance (#678).

One nullable column on `workspace_invitations`, one definer function that sets it, and one
step added to `workspace_invitation_accept`:

- `workspace_invitation_set_group` names the group, once, on a pending, unexpired invitation,
  in the transaction that created it. It runs the administrator check every invitation path
  runs (0059's `ACTOR_CHECK`: workspace-wide `access.manage`, so an administrator narrowed to
  Spaces cannot reach it), and refuses with `INVALID_GROUP` a group of another tenant, a group
  carrying an Administrator or Policy manager grant, a group carrying any other grant the
  invitation's own grants do not cover (the same role, and either a workspace-wide invitation
  grant or the same Space), and an invitation that grants no Approver role: an accepted invitee
  is a managed person, who decides only through an Approver grant, so a group named for anyone
  else would route work to someone who can decide nothing. A refusal rolls the whole creation
  back.
- Step 8b of the acceptance applies the group only then, right after step 8's `access_change`,
  which has already taken the tenant fence and re-checked the inviter's authority, so a group
  change, which also goes through `access_change`, is ordered against it. The group is checked
  again: gone (`GROUP_GONE`), now carrying an Administrator or Policy manager grant
  (`GROUP_ROLES`), now carrying a grant the invitation does not cover (`GROUP_SCOPE`), or at
  the 100 members `access_change` allows (`GROUP_FULL`), it is skipped and the reason
  returned; the person still joins with the grants the invitation showed. Otherwise the person
  becomes a member. The function's result names the outcome as `reviewer_group`.

The column has no foreign key: a group may be deleted while an invitation waits, and the
acceptance answers that case itself. The acceptance is patched in place with the exact-once
`_replace` 0061 introduced, copied here by choice as 0070 copies what it needs, so this
revision's text stays fixed whatever later revisions do to 0061. The downgrade refuses while a
pending invitation names a group, because dropping the column would silently lose a choice an
administrator made, and otherwise undoes the three patches byte for byte.
"""

from alembic import op
from sqlalchemy import text

revision = "0083_invitation_reviewer_group"
down_revision = "0082_workspace_entry"
branch_labels = None
depends_on = None

SIGNATURE = "workspace_invitation_set_group(uuid, uuid, uuid, timestamptz)"

# The tenant, the clock and the acting administrator, verbatim from 0059.
ACTOR_CHECK = r"""
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active)
       OR NOT EXISTS (SELECT 1 FROM execbound.principals p WHERE p.tenant_id = v_tenant
                       AND p.principal_id = p_actor AND p.active)
       OR NOT execbound.access_has_permission(p_actor, 'access.manage', NULL, false) THEN
        RAISE EXCEPTION 'FORBIDDEN';
    END IF;
"""

# A grant the group carries that none of the invitation's grants covers. The group is covered
# when this finds nothing. A grant is covered by an invitation grant of the same role that is
# workspace-wide or names the same Space; a workspace-wide group grant is therefore covered only
# by a workspace-wide invitation grant, because `(g->>'space_id')::uuid = NULL` is never true.
GROUP_COVERED = """SELECT 1 FROM execbound.access_role_grants r
                WHERE r.tenant_id = v_tenant AND r.group_id = {group}
                  AND NOT EXISTS (
                      SELECT 1 FROM jsonb_array_elements({grants}) g
                       WHERE g->>'role' = r.role
                         AND (g->>'space_id' IS NULL OR (g->>'space_id')::uuid = r.space_id))"""

# A grant the group carries that is more than review.
GROUP_RAISED = """SELECT 1 FROM execbound.access_role_grants r
                WHERE r.tenant_id = v_tenant AND r.group_id = {group}
                  AND r.role IN ('administrator', 'policy_manager')"""

SET_GROUP = (
    r"""
CREATE FUNCTION execbound.workspace_invitation_set_group(
    p_actor uuid, p_invitation uuid, p_group uuid, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_invitation execbound.workspace_invitations%ROWTYPE;
BEGIN
    IF v_tenant IS NULL OR p_actor IS NULL OR p_invitation IS NULL OR p_group IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
"""
    + ACTOR_CHECK
    + r"""
    SELECT * INTO v_invitation FROM execbound.workspace_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'NOT_FOUND';
    END IF;
    IF v_invitation.state <> 'PENDING' OR v_invitation.expires_at <= p_now
       OR v_invitation.reviewer_group_id IS NOT NULL THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- Row security already hides another tenant's group; the tenant is named anyway.
    IF NOT EXISTS (SELECT 1 FROM execbound.access_groups g
                    WHERE g.tenant_id = v_tenant AND g.group_id = p_group) THEN
        RAISE EXCEPTION 'INVALID_GROUP';
    END IF;
    IF EXISTS ("""
    + GROUP_RAISED.format(group="p_group")
    + r""") THEN
        RAISE EXCEPTION 'INVALID_GROUP';
    END IF;
    IF EXISTS ("""
    + GROUP_COVERED.format(group="p_group", grants="v_invitation.grants")
    + r""") THEN
        RAISE EXCEPTION 'INVALID_GROUP';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_invitation.grants) g
                    WHERE g->>'role' = 'approver') THEN
        RAISE EXCEPTION 'INVALID_GROUP';
    END IF;
    UPDATE execbound.workspace_invitations SET reviewer_group_id = p_group
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
END $$
"""
)

ACCEPT_DECLARE = """\
    v_rejoin boolean := false;
"""
ACCEPT_DECLARE_GROUP = """\
    v_rejoin boolean := false;
    v_group_outcome jsonb;
"""

ACCEPT_GRANTS = """\
        jsonb_build_object('grants', v_invitation.grants));
"""
ACCEPT_GRANTS_GROUP = (
    ACCEPT_GRANTS
    + """
    -- 8b. The reviewer group the invitation named, applied only now, under the fence
    --     access_change took, and only while it grants no more than the invitation shows
    --     (0083). A skipped group never refuses the acceptance; the outcome says why.
    IF v_invitation.reviewer_group_id IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM execbound.access_groups g
                        WHERE g.tenant_id = v_tenant
                          AND g.group_id = v_invitation.reviewer_group_id) THEN
            v_group_outcome := jsonb_build_object('group_id', v_invitation.reviewer_group_id,
                'applied', false, 'reason', 'GROUP_GONE');
        ELSIF EXISTS ("""
    + GROUP_RAISED.format(group="v_invitation.reviewer_group_id")
    + """) THEN
            v_group_outcome := jsonb_build_object('group_id', v_invitation.reviewer_group_id,
                'applied', false, 'reason', 'GROUP_ROLES');
        ELSIF EXISTS ("""
    + GROUP_COVERED.format(group="v_invitation.reviewer_group_id", grants="v_invitation.grants")
    + """) THEN
            v_group_outcome := jsonb_build_object('group_id', v_invitation.reviewer_group_id,
                'applied', false, 'reason', 'GROUP_SCOPE');
        ELSIF (SELECT count(*) FROM execbound.access_group_members m
                WHERE m.tenant_id = v_tenant
                  AND m.group_id = v_invitation.reviewer_group_id) >= 100 THEN
            v_group_outcome := jsonb_build_object('group_id', v_invitation.reviewer_group_id,
                'applied', false, 'reason', 'GROUP_FULL');
        ELSE
            INSERT INTO execbound.access_group_members(tenant_id, group_id, principal_id)
            VALUES (v_tenant, v_invitation.reviewer_group_id, p_principal)
            ON CONFLICT DO NOTHING;
            v_group_outcome := jsonb_build_object('group_id', v_invitation.reviewer_group_id,
                'applied', true, 'reason', NULL);
        END IF;
    END IF;
"""
)

ACCEPT_RETURN = """\
        'inviter_id', v_invitation.inviter_id, 'changed', v_changed);
"""
ACCEPT_RETURN_GROUP = """\
        'inviter_id', v_invitation.inviter_id, 'changed', v_changed,
        'reviewer_group', v_group_outcome);
"""

# (function, fragment as the previous head leaves it, fragment as this revision leaves it),
# applied in order on upgrade and undone in reverse on downgrade.
PATCHES = (
    ("workspace_invitation_accept", ACCEPT_DECLARE, ACCEPT_DECLARE_GROUP),
    ("workspace_invitation_accept", ACCEPT_GRANTS, ACCEPT_GRANTS_GROUP),
    ("workspace_invitation_accept", ACCEPT_RETURN, ACCEPT_RETURN_GROUP),
)


def _replace(function: str, before: str, after: str) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = :name"
        ),
        {"name": function},
    ).scalar_one()
    # A definition that no longer carries the fragment verbatim, exactly once, was changed by
    # something this migration does not know, and is refused rather than guessed at.
    if definition.count(before) != 1:
        raise RuntimeError(f"{function} no longer has the fragment 0083 patches")
    # CREATE OR REPLACE keeps the function's owner, its SECURITY DEFINER and its grants. The
    # acceptance declares `%ROWTYPE` variables, and SQLAlchemy always hands the driver a
    # parameter container, so every percent sign is doubled for psycopg.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute("ALTER TABLE execbound.workspace_invitations ADD COLUMN reviewer_group_id uuid")
    op.execute(SET_GROUP)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{SIGNATURE} TO execbound_app")
    for role in ("anon", "authenticated", "service_role"):
        if role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM {role}")
    for function, before, after in PATCHES:
        _replace(function, before, after)


def downgrade() -> None:
    # An owner that does not bypass row security sees no tenant's invitation unfenced, so
    # FORCE is lifted around the count and put back before anything else happens.
    op.execute("ALTER TABLE execbound.workspace_invitations NO FORCE ROW LEVEL SECURITY")
    named = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.workspace_invitations "
                "WHERE state = 'PENDING' AND reviewer_group_id IS NOT NULL)"
            )
        )
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.workspace_invitations FORCE ROW LEVEL SECURITY")
    if named:
        raise RuntimeError(
            "Pending invitations name reviewer groups; revoke them or let them expire "
            "before downgrading"
        )
    for function, before, after in reversed(PATCHES):
        _replace(function, after, before)
    op.execute(f"DROP FUNCTION execbound.{SIGNATURE}")
    op.execute("ALTER TABLE execbound.workspace_invitations DROP COLUMN reviewer_group_id")
