# SPDX-License-Identifier: AGPL-3.0-only
"""A workspace switch carries a recent verification, and records where it came from (#678).

`account_switch` used to start every destination session without assurance, so a person who had
just entered a code in one workspace was asked for another on switching to the next. It now
carries the source session's verification into the destination session when, inside the switch's
own transaction, the source session's `session_assurance` row is for the account's current factor
version, the factor is enabled, and the verification is under thirty minutes old: the step-up
window, `mfa.STEP_UP_WINDOW`, which a test holds this literal to. The carried row keeps the
source's own `version`, `verified_at` and `method`, so the window never restarts.

Each carry is recorded for the account in `user_security_events`, which gains four nullable
columns naming the source workspace and session and the destination workspace and session. A
check holds them to the `assurance_carried` kind, all four together. The table's row security
admits a row under the account's own setting alone, so neither workspace's administrators read
the other's identifiers. The function also returns whether it carried, the method and the
original verification time, which the caller records in the destination's own audit chain.

`account_switch` is patched in place, as `0082_workspace_entry` patches it: the live definition
is read, each fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the owner,
`SECURITY DEFINER`, `search_path` and the grants. The signature does not change. The downgrade
restores the definition through the same fragments, then drops the check and the columns; rows
already carried stay, as ordinary assurance rows of sessions that exist.
"""

from alembic import op
from sqlalchemy import text

revision = "0089_assurance_carry"
down_revision = "0088_monitor_entra_consent"
branch_labels = None
depends_on = None

COLUMNS = "source_tenant_id, source_session_id, destination_tenant_id, destination_session_id"

# The declarations' last line (0054).
DECLARE = "    member execbound.workspace_memberships; k text; expiry timestamptz;"
DECLARE_CARRIED = DECLARE + "\n    carried execbound.session_assurance;"
# The last check before the function first moves the tenant setting to the destination (0054).
# Its last two lines each occur twice in the function; the three together occur once. The read
# goes between the check and the move, while the setting is still the source's: the source row
# is invisible under the destination's row security.
READ_ANCHOR = (
    "        OR abs(extract(epoch FROM (p_now-now())))>300\n"
    "        THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;\n"
    "    PERFORM set_config('execbound.tenant_id',p_destination::text,true);"
)
READ = (
    "        OR abs(extract(epoch FROM (p_now-now())))>300\n"
    "        THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;\n"
    "    -- The source's own verification, carried only for the account's current factor\n"
    "    -- version and only within the step-up window (`mfa.STEP_UP_WINDOW`).\n"
    "    SELECT sa.* INTO carried FROM execbound.session_assurance sa\n"
    "        JOIN execbound.user_factors f ON f.account_id=a\n"
    "        WHERE sa.tenant_id=t AND sa.session_id=p_previous AND f.enabled_at IS NOT NULL\n"
    "          AND sa.version=f.version AND sa.verified_at<=p_now\n"
    "          AND sa.verified_at>p_now-interval '30 minutes';\n"
    "    PERFORM set_config('execbound.tenant_id',p_destination::text,true);"
)
# The comment after the destination session is inserted (0054) and the entry stamp after it
# (0082). The tenant setting there is the destination's and the account setting the account's.
WRITE_ANCHOR = (
    "    -- The destination starts without assurance. Its current policy and the global\n"
    "    -- factor require a new verification when the new session is loaded.\n"
    "    UPDATE execbound.workspace_memberships SET last_entered_at=p_now"
    " WHERE account_id=a AND tenant_id=p_destination;"
)
WRITE = (
    "    -- The destination carries the source's assurance only for the same factor version\n"
    "    -- within the step-up window; otherwise it starts without assurance.\n"
    "    UPDATE execbound.workspace_memberships SET last_entered_at=p_now"
    " WHERE account_id=a AND tenant_id=p_destination;\n"
    "    IF carried.session_id IS NOT NULL THEN\n"
    "        INSERT INTO execbound.session_assurance(tenant_id,session_id,version,verified_at,\n"
    "            method) VALUES(p_destination,p_next,carried.version,carried.verified_at,\n"
    "            carried.method);\n"
    "        INSERT INTO execbound.user_security_events(account_id,kind,occurred_at,\n"
    "            source_tenant_id,source_session_id,destination_tenant_id,destination_session_id)\n"
    "            VALUES(a,'assurance_carried',p_now,t,p_previous,p_destination,p_next);\n"
    "    END IF;"
)
# The returned object's last line (0054).
RETURN_ANCHOR = "        'expires_at',expiry,'credential_expires_at',x.absolute_expires_at);"
RETURN = (
    "        'expires_at',expiry,'credential_expires_at',x.absolute_expires_at,\n"
    "        'assurance_carried',carried.session_id IS NOT NULL,'carried_method',carried.method,\n"
    "        'carried_verified_at',carried.verified_at);"
)
PATCHES = (
    (DECLARE, DECLARE_CARRIED),
    (READ_ANCHOR, READ),
    (WRITE_ANCHOR, WRITE),
    (RETURN_ANCHOR, RETURN),
)


def _replace(before: str, after: str) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = 'account_switch'"
        )
    ).scalar_one()
    # A definition that no longer carries the fragment exactly once was changed by something
    # this migration does not know, and is refused rather than guessed at.
    if definition.count(before) != 1:
        raise RuntimeError(f"account_switch no longer has the fragment {revision} patches")
    # Straight to the driver, every percent sign doubled: psycopg reads `%` as a placeholder.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def upgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.user_security_events "
        "ADD COLUMN source_tenant_id uuid, ADD COLUMN source_session_id uuid, "
        "ADD COLUMN destination_tenant_id uuid, ADD COLUMN destination_session_id uuid, "
        "ADD CONSTRAINT user_security_events_carry CHECK ("
        f"num_nulls({COLUMNS}) = 4 "
        f"OR (kind = 'assurance_carried' AND num_nonnulls({COLUMNS}) = 4))"
    )
    for before, after in PATCHES:
        _replace(before, after)


def downgrade() -> None:
    for before, after in reversed(PATCHES):
        _replace(after, before)
    op.execute(
        "ALTER TABLE execbound.user_security_events "
        "DROP CONSTRAINT user_security_events_carry, "
        "DROP COLUMN source_tenant_id, DROP COLUMN source_session_id, "
        "DROP COLUMN destination_tenant_id, DROP COLUMN destination_session_id"
    )
