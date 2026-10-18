# SPDX-License-Identifier: AGPL-3.0-only
"""An account with no password may set its first one (#593).

An account made through Google or GitHub has no password (decision D3 of the provider signup
design), and `user_security_change`'s `password` operation only replaces an existing row,
conditioned on its current hash. This revision adds `password_set`, which inserts the account's
first `user_passwords` row and refuses `PASSWORD_EXISTS` when it already has one, so it never
replaces a password, however it is called.

It asks exactly what `link_begin` and `link_finish` ask before a provider may be added: a
verified factor within the step-up window when one is enabled, an account session signed in
within five minutes, and a verified address. Like every other change to how the account signs
in, it moves the account's version and ends its other sessions, keeping the one that made it.

The function is patched in place, as `0067_step_up_window` patches it: the live definition is
read, each fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the owner,
`SECURITY DEFINER` and the grants.
"""

from alembic import op
from sqlalchemy import text

revision = "0070_first_password"
down_revision = "0069_provider_signup"
branch_labels = None
depends_on = None

FUNCTION = "user_security_change"

BRANCH_BEFORE = "    ELSIF p_operation='password' THEN"
BRANCH_AFTER = """    ELSIF p_operation='password_set' THEN
        IF (f.enabled_at IS NOT NULL AND NOT fresh) OR
            NOT EXISTS(SELECT 1 FROM execbound.account_sessions x WHERE x.account_id=v_account
                AND x.session_id=s.account_session_id AND x.created_at>p_now-interval '5 minutes'
                AND x.created_at<=p_now) OR NOT EXISTS(
                    SELECT 1 FROM execbound.user_accounts WHERE account_id=v_account
                    AND email_verified_at IS NOT NULL)
            THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        INSERT INTO execbound.user_passwords(account_id,algorithm,n,r,p,dklen,salt,hash,
            created_at,updated_at)
            VALUES(v_account,p_data->>'algorithm',(p_data->>'n')::integer,
                (p_data->>'r')::integer,(p_data->>'p')::integer,(p_data->>'dklen')::integer,
                p_data->>'salt',p_data->>'hash',p_now,p_now)
            ON CONFLICT(account_id) DO NOTHING;
        IF NOT FOUND THEN RAISE EXCEPTION 'PASSWORD_EXISTS'; END IF;
    ELSIF p_operation='password' THEN"""

ROTATION_BEFORE = "'password','link_finish') THEN"
ROTATION_AFTER = "'password','password_set','link_finish') THEN"


def _replace(pairs: tuple[tuple[str, str], ...]) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = :name"
        ),
        {"name": FUNCTION},
    ).scalar_one()
    for before, after in pairs:
        # A definition that no longer carries the fragment exactly once was changed by
        # something this migration does not know, and is refused rather than guessed at.
        if definition.count(before) != 1:
            raise RuntimeError(f"{FUNCTION} no longer has a fragment {revision} patches")
        definition = definition.replace(before, after)
    # Straight to the driver, every percent sign doubled: psycopg reads `%` as a placeholder.
    conn.exec_driver_sql(definition.replace("%", "%%"))


def upgrade() -> None:
    _replace(((BRANCH_BEFORE, BRANCH_AFTER), (ROTATION_BEFORE, ROTATION_AFTER)))


def downgrade() -> None:
    # A first password already set stays: it is an ordinary `user_passwords` row, which
    # `password` changes and every sign-in reads exactly like any other.
    _replace(((ROTATION_AFTER, ROTATION_BEFORE), (BRANCH_AFTER, BRANCH_BEFORE)))
