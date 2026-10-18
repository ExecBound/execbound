# SPDX-License-Identifier: AGPL-3.0-only
"""When an account last entered each of its workspaces (#678).

`workspace_memberships.last_entered_at` is a nullable timestamp, set by the two definer functions
that enter a workspace, so the runtime role gains no write on the table:

- `account_session_open` sets it on the account's active membership in the session's tenant
  when it opens the account session: every password and provider sign-in of an account.
- `account_switch` sets it on the destination membership.

A sign-in with no navigation hint opens the eligible workspace entered most recently, and the
workspace list carries the column so the switcher can order by it. The stamp grants nothing: it
only orders a choice among memberships each usable on its own, and it is the account's own
record of its own entries.

Both functions are patched in place, as `0067_step_up_window` patches its two: the live
definition is read, each fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps
the owner, `SECURITY DEFINER`, `search_path` and the grants. Neither signature changes. The
downgrade restores both definitions through the same fragments, then drops the column.
"""

from alembic import op
from sqlalchemy import text

revision = "0082_workspace_entry"
down_revision = "0081_finding_acknowledgement"
branch_labels = None
depends_on = None

# The last line of the account session insert in `account_session_open` (0054). The tenant
# setting there is the session's own and the account setting is the proof's account.
OPEN_ANCHOR = "p_now+interval '8 hours',a.version,proof.method,t,p_session);"
OPEN_STAMP = (
    "\n    UPDATE execbound.workspace_memberships SET last_entered_at=p_now"
    "\n        WHERE account_id=a.account_id AND tenant_id=t AND active;"
)
# The comment after the destination session is inserted in `account_switch` (0054). It stays
# true: the destination still starts without assurance. The tenant setting there is the
# destination's, and `member` is its active, eligible membership.
SWITCH_ANCHOR = (
    "-- The destination starts without assurance. Its current policy and the global\n"
    "    -- factor require a new verification when the new session is loaded."
)
SWITCH_STAMP = (
    "\n    UPDATE execbound.workspace_memberships SET last_entered_at=p_now"
    " WHERE account_id=a AND tenant_id=p_destination;"
)
PATCHES = (
    ("account_session_open", OPEN_ANCHOR, OPEN_ANCHOR + OPEN_STAMP),
    ("account_switch", SWITCH_ANCHOR, SWITCH_ANCHOR + SWITCH_STAMP),
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
    # A definition that no longer carries the fragment exactly once was changed by something
    # this migration does not know, and is refused rather than guessed at.
    if definition.count(before) != 1:
        raise RuntimeError(f"{function} no longer has the fragment {revision} patches")
    # Straight to the driver, every percent sign doubled: psycopg reads `%` as a placeholder.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def upgrade() -> None:
    op.execute("ALTER TABLE execbound.workspace_memberships ADD COLUMN last_entered_at timestamptz")
    for function, before, after in PATCHES:
        _replace(function, before, after)


def downgrade() -> None:
    for function, before, after in reversed(PATCHES):
        _replace(function, after, before)
    op.execute("ALTER TABLE execbound.workspace_memberships DROP COLUMN last_entered_at")
