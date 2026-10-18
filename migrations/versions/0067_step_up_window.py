"""A verified factor steps a session up for thirty minutes, not five (decided 28 September 2026).

`account_security_change` and `user_security_change` each decide once, in `fresh`, whether the
session's factor was verified recently enough for a security change: replacing recovery codes,
turning a factor off, the organization requirement, adding or removing a passkey, replacing an
authenticator, rotating the session after a verification, linking a provider and, for an
account, changing its password. The console API's step-up (`mfa.require_recent_factor`) and the
Python checks in front of each of those changes read `mfa.STEP_UP_WINDOW`, which is now thirty
minutes; this revision moves the database's own check to the same thirty minutes, so a change
the Python check admits at minute twenty is not refused beneath it.

Only `fresh` moves. The other five-minute intervals in these functions are different windows
and keep their values: how new a session must be to stage a first authenticator or to link a
provider (the sign-in's own age), how long a staged authenticator, a passkey challenge and a
provider link last.

Both functions are patched in place, as `0066_max_agents` patches its five: the live definition
is read, the fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the owner,
`SECURITY DEFINER` and the grants.
"""

from alembic import op
from sqlalchemy import text

revision = "0067_step_up_window"
down_revision = "0066_max_agents"
branch_labels = None
depends_on = None

FIVE = "a.verified_at>p_now-interval '5 minutes'"
THIRTY = "a.verified_at>p_now-interval '30 minutes'"
FUNCTIONS = ("account_security_change", "user_security_change")


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
    for function in FUNCTIONS:
        _replace(function, FIVE, THIRTY)


def downgrade() -> None:
    for function in reversed(FUNCTIONS):
        _replace(function, THIRTY, FIVE)
