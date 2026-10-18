"""A principal a re-invitation replaced is retired for good.

When a removed member accepts a new invitation, `workspace_invitation_accept` makes a fresh
principal with the invitation's grants and re-points the account's one membership at it. The
old principal stays deactivated with its old grants, and nothing stopped an administrator from
reactivating it afterwards: a live approver or administrator that no membership points at,
counted by `access_has_permission` and by the `LAST_ADMINISTRATOR` check, beside the new
principal for the same address.

`principals.replaced_by` names the principal that took the old one's place, a foreign key
within the tenant with its covering index, and a check forbids a replaced principal from
being active or naming itself, so no code path can bring one back. The acceptance sets it
when it re-points a membership, and `admin_reactivate_principal` refuses a replaced principal
with `PRINCIPAL_REPLACED` after its row lock and before any other effect.

Both functions are patched in place, as `0057_api_key_never` patches its function: the live
definition is read, each patch replaces one exact fragment that must occur exactly once (two
patches in the acceptance, one in the reactivation), and `CREATE OR REPLACE` keeps the owner,
`SECURITY DEFINER` and the grants. `admin_reactivate_principal` is patched rather than
restated from `0044_hosted_free`, because `0047_access_control` rewrote it after 0044 (the
tenant fence at its top and the role-aware actor check), and restating 0044's text would
quietly undo both.

Lock order. The acceptance's documented caller order is the account lock, then the tenant
fence, then the function. The fence is the `tenant_policy_control` row. Reactivation takes
that row first, inside the function (0047), and then the target principal's row
(`FOR NO KEY UPDATE`, 0044). The acceptance used to read whether the old principal was active
with no lock, and reached the fence only later, inside `access_change`; a reactivation that
committed in between left the acceptance acting on a stale answer. It now takes the fence,
then the old principal's row, both before it decides, so it acquires the two in the same order
the reactivation does and the two serialize whoever calls them: the loser waits, reads what
the winner committed, and refuses with its own code (`ALREADY_MEMBER` or
`PRINCIPAL_REPLACED`), never a check violation or a deadlock. Callers that already hold the
fence, as both services do, take it again at no cost.

Nothing is backfilled. No hosted database has applied 0059, so no re-pointed membership
exists there, and a membership re-pointed locally before this revision simply names no
replacement. The downgrade refuses while any principal names its replacement, because
dropping the column would lose the one fact that keeps that principal retired.
"""

from alembic import op
from sqlalchemy import text

revision = "0061_replaced_principals"
down_revision = "0060_sample_targets"
branch_labels = None
depends_on = None

# Step 6 of the acceptance, where it decides whether the account's membership points at a
# removed member's principal. Before it decides, it takes the tenant fence and then that
# principal's row, the order `admin_reactivate_principal` takes the same two locks in.
ACCEPT_DECISION = """\
        SELECT p.active INTO v_former FROM execbound.workspace_memberships m
          JOIN execbound.principals p
            ON p.tenant_id = m.tenant_id AND p.principal_id = m.principal_id
         WHERE m.account_id = v_account_id AND m.tenant_id = v_tenant;
"""
ACCEPT_DECISION_LOCKED = """\
        -- The tenant fence, then the old principal's row, both before deciding (0061): a
        -- reactivation takes the same two in the same order, so whichever commits first
        -- decides and the other reads its outcome. Already held when the caller fenced.
        INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at)
        VALUES (v_tenant, now()) ON CONFLICT (tenant_id) DO NOTHING;
        PERFORM 1 FROM execbound.tenant_policy_control WHERE tenant_id = v_tenant FOR UPDATE;
        SELECT p.active INTO v_former FROM execbound.workspace_memberships m
          JOIN execbound.principals p
            ON p.tenant_id = m.tenant_id AND p.principal_id = m.principal_id
         WHERE m.account_id = v_account_id AND m.tenant_id = v_tenant
           FOR NO KEY UPDATE OF p;
"""

# Step 9, the re-point. The principal the membership pointed at is retired for good.
ACCEPT_REPOINT = """\
    IF v_rejoin THEN
        UPDATE execbound.workspace_memberships
"""
ACCEPT_REPOINT_REPLACED = """\
    IF v_rejoin THEN
        -- The old principal is retired for good (0061): it names the one that replaced it,
        -- and the principals_replaced_retired check keeps it from ever being active again.
        UPDATE execbound.principals p SET replaced_by = p_principal
          FROM execbound.workspace_memberships m
         WHERE m.account_id = v_account_id AND m.tenant_id = v_tenant
           AND p.tenant_id = m.tenant_id AND p.principal_id = m.principal_id;
        UPDATE execbound.workspace_memberships
"""

# Reactivation's own row lock, and the refusal right after it, before any other effect.
REACTIVATE_LOCK = """\
    SELECT p.kind, p.deactivated_at INTO v_kind, v_deactivated
      FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
       FOR NO KEY UPDATE;
"""
REACTIVATE_LOCK_REFUSED = (
    REACTIVATE_LOCK
    + """\
    -- A principal a re-invitation replaced is retired for good (0061); the person is managed
    -- through the principal that replaced it.
    IF EXISTS (SELECT 1 FROM execbound.principals p
                WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
                  AND p.replaced_by IS NOT NULL) THEN
        RAISE EXCEPTION 'PRINCIPAL_REPLACED';
    END IF;
"""
)

# (function, fragment as 0059 leaves it, fragment as this revision leaves it), applied in
# order on upgrade and undone in reverse on downgrade.
PATCHES = (
    ("workspace_invitation_accept", ACCEPT_DECISION, ACCEPT_DECISION_LOCKED),
    ("workspace_invitation_accept", ACCEPT_REPOINT, ACCEPT_REPOINT_REPLACED),
    ("admin_reactivate_principal", REACTIVATE_LOCK, REACTIVATE_LOCK_REFUSED),
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
        raise RuntimeError(f"{function} no longer has the fragment 0061 patches")
    # CREATE OR REPLACE keeps the function's owner, its SECURITY DEFINER and its grants. The
    # body goes straight to the driver, as 0057's does. SQLAlchemy always hands the driver a
    # parameter container, even an empty one, so psycopg reads `%` as a placeholder: the
    # acceptance declares `%ROWTYPE` variables, so every percent sign is doubled here.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def upgrade() -> None:
    op.execute("ALTER TABLE execbound.principals ADD COLUMN replaced_by uuid")
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_replaced_by "
        "FOREIGN KEY (tenant_id, replaced_by) "
        "REFERENCES execbound.principals (tenant_id, principal_id)"
    )
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_replaced_retired "
        "CHECK (replaced_by IS NULL OR (NOT active AND replaced_by <> principal_id))"
    )
    # Every foreign key has a covering index (`test_foreign_keys_have_covering_indexes`).
    op.execute(
        "CREATE INDEX principals_replacement ON execbound.principals (tenant_id, replaced_by)"
    )
    for function, before, after in PATCHES:
        _replace(function, before, after)


def downgrade() -> None:
    # An owner that does not bypass row security sees no tenant's principal unfenced, so
    # FORCE is lifted around the count and put back before anything else happens.
    op.execute("ALTER TABLE execbound.principals NO FORCE ROW LEVEL SECURITY")
    retained = (
        op.get_bind()
        .execute(
            text("SELECT EXISTS (SELECT 1 FROM execbound.principals WHERE replaced_by IS NOT NULL)")
        )
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.principals FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "Replaced principals require a verified full restore; lossy downgrade refused"
        )
    for function, before, after in reversed(PATCHES):
        _replace(function, after, before)
    op.execute("DROP INDEX execbound.principals_replacement")
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_replaced_retired")
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_replaced_by")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN replaced_by")
