# SPDX-License-Identifier: AGPL-3.0-only
"""A sign-in lasts two days and a console session twelve hours idle (decided 19 October 2026).

The credential a sign-in mints used to live eight hours and the session it opened fifteen
minutes between activity. The credential now lives two days, which is the longest a session may
be renewed for, and a session ends after twelve hours without activity. The application's
renewal cadence is unchanged: a session is extended on activity every seven and a half minutes.

Four functions carry the old numbers and are patched in place, as `0067_step_up_window` patches
two: the live definition is read, each fragment must occur in it exactly once, and
`CREATE OR REPLACE` keeps the owner, `SECURITY DEFINER` and the grants.

* `sign_in_credential` and `directory_sign_in` refuse a credential longer than the sign-in
  lifetime: eight hours become two days. (`directory_sign_in` was not on the plan's list; it
  mints the same credential and would refuse a two-day one.)
* `account_session_open` opens an account session with a twelve-hour expiry and a two-day
  absolute end.
* `account_session_touch` extends an account session twelve hours, never past its absolute end.
* `account_switch` is deliberately NOT patched: the destination session it opens starts at
  fifteen minutes, because it owes the second factor unless the source's verification was
  carried (a carry happens only within thirty minutes), and a session that owes the factor is
  never renewed. The first load that owes nothing extends it to twelve hours through
  `renew_human_session`, and the account session's own touch does the same for its row.

Two functions are added for the directory recheck, which at a session's two-day end is due on
every request: `directory_recheck_claim` moves a directory sign-in's `verified_at` to now only
when it still reads the value the caller saw, and answers the new value or NULL, so that of
several simultaneous requests exactly one calls the directory; `directory_recheck_release`
puts the old value back when the directory could not answer, so an unreachable directory is
still refused once the grace passes. Both are definers for the runtime role alone.

`human_sessions_check` is the table's own ceiling and moves with them: a session may not outlive
its credential or two days from its creation. It is dropped and re-added `NOT VALID` and then
validated, so no old row is left unchecked. Every existing row already satisfies the wider bound.

A session opened before this revision keeps the end it was given: nothing rewrites an existing
`expires_at`, and a live session is simply renewed twelve hours at a time from now on.

The downgrade reverses every patch. Before it re-adds the eight-hour ceiling it ends any
session that would violate it: a session whose expiry is more than eight hours after its
creation is revoked and its expiry cut back to the eight hours (row-level security is lifted
around that one statement, as `0027_approval_deadline` did, so every tenant's rows are reached).
A signed-in person signs in again. Account sessions are not cut back: their own table has only
the absolute end, which the restored functions already respect.
"""

from alembic import op
from sqlalchemy import text

revision = "0100_longer_sessions"
down_revision = "0099_scout_agents_page"
branch_labels = None
depends_on = None

CREDENTIAL = ("> interval '8 hours' THEN", "> interval '2 days' THEN")
OPEN_IDLE = ("p_now+interval '15 minutes'", "p_now+interval '12 hours'")
OPEN_ABSOLUTE = ("p_now+interval '8 hours'", "p_now+interval '2 days'")
IDLE = ("interval '15 minutes'", "interval '12 hours'")

PATCHES = (
    ("sign_in_credential", (CREDENTIAL,)),
    ("directory_sign_in", (CREDENTIAL,)),
    ("account_session_open", (OPEN_IDLE, OPEN_ABSOLUTE)),
    ("account_session_touch", (IDLE,)),
)

SUPABASE_ROLES = ("anon", "authenticated", "service_role")
CLAIM = "directory_recheck_claim(uuid, timestamptz)"
RELEASE = "directory_recheck_release(uuid, timestamptz, timestamptz)"
CREATE_CLAIM = """
CREATE FUNCTION execbound.directory_recheck_claim(p_credential uuid, p_seen timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_claimed timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET verified_at = now()
     WHERE tenant_id = v_tenant AND credential_id = p_credential
       AND revoked_reason IS NULL AND verified_at = p_seen
    RETURNING verified_at INTO v_claimed;
    RETURN v_claimed;
END $$
"""
CREATE_RELEASE = """
CREATE FUNCTION execbound.directory_recheck_release(
    p_credential uuid, p_claimed timestamptz, p_seen timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET verified_at = p_seen
     WHERE tenant_id = v_tenant AND credential_id = p_credential
       AND revoked_reason IS NULL AND verified_at = p_claimed;
END $$
"""

BOUND = (
    "expires_at > created_at AND expires_at <= credential_expires_at "
    "AND expires_at <= created_at + interval '{}'"
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


def _bound(interval: str) -> None:
    op.execute(
        "ALTER TABLE execbound.human_sessions DROP CONSTRAINT human_sessions_check, "
        f"ADD CONSTRAINT human_sessions_check CHECK ({BOUND.format(interval)}) NOT VALID"
    )
    op.execute("ALTER TABLE execbound.human_sessions VALIDATE CONSTRAINT human_sessions_check")


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    for function, fragments in PATCHES:
        for before, after in fragments:
            _replace(function, before, after)
    _bound("2 days")
    for body, signature in ((CREATE_CLAIM, CLAIM), (CREATE_RELEASE, RELEASE)):
        op.execute(body)
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in SUPABASE_ROLES:
            if _role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION execbound.{RELEASE}")
    op.execute(f"DROP FUNCTION execbound.{CLAIM}")
    # Sessions that outlive the old ceiling are ended and cut back to it before it returns.
    op.execute("ALTER TABLE execbound.human_sessions NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    op.execute(
        "UPDATE execbound.human_sessions SET revoked_at = COALESCE(revoked_at, now()), "
        "expires_at = created_at + interval '8 hours' "
        "WHERE expires_at > created_at + interval '8 hours'"
    )
    # Row security comes back for the rest of the downgrade's transaction, as 0101's does.
    op.execute("RESET row_security")
    op.execute("ALTER TABLE execbound.human_sessions FORCE ROW LEVEL SECURITY")
    _bound("8 hours")
    for function, fragments in reversed(PATCHES):
        for before, after in reversed(fragments):
            _replace(function, after, before)
