# SPDX-License-Identifier: AGPL-3.0-only
"""A monitoring finding's acknowledgement takes a note and becomes final (#678).

An administrator acknowledging a finding may now say why, in at most 500 characters, and the
note is kept with the acknowledgement. The store trims it and refuses one shaped like a secret
before it reaches this table; the checks here hold its length and keep a note off a finding
nobody has acknowledged. The runtime gains an update grant on the one new column.

An acknowledgement is final from here on. A monitoring acknowledgement records that someone
looked, which stays true, and the note and its audit event must never disagree with the row,
so a trigger refuses any change to `acknowledged_at`, `acknowledged_by` or
`acknowledgement_note` once `acknowledged_at` is set, for every role. It is not a definer
function and no one but its owner may call it.

A partial index holds the open findings by tenant and time, for the open queue and its count.

The downgrade refuses while any note is retained, rather than drop what an administrator wrote,
and otherwise removes the trigger, its function, the index, both checks and the column (which
takes its grant with it).
"""

from alembic import op
from sqlalchemy import text

revision = "0081_finding_acknowledgement"
down_revision = "0080_notification_kinds"
branch_labels = None
depends_on = None

SUPABASE_ROLES = ("anon", "authenticated", "service_role")
SIGNATURE = "execbound.monitor_findings_acknowledged_once()"

ONCE = """
CREATE FUNCTION execbound.monitor_findings_acknowledged_once() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.acknowledged_at IS NOT NULL AND (
        NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at
        OR NEW.acknowledged_by IS DISTINCT FROM OLD.acknowledged_by
        OR NEW.acknowledgement_note IS DISTINCT FROM OLD.acknowledgement_note
    ) THEN
        RAISE EXCEPTION 'monitor finding acknowledgement is final'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$
"""


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :r)"), {"r": role})
        .scalar_one()
    )


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.monitor_findings
            ADD COLUMN acknowledgement_note text,
            ADD CONSTRAINT monitor_findings_note_length CHECK (
                acknowledgement_note IS NULL OR length(acknowledgement_note) BETWEEN 1 AND 500),
            ADD CONSTRAINT monitor_findings_note_acknowledged CHECK (
                acknowledgement_note IS NULL OR acknowledged_at IS NOT NULL)
    """)
    op.execute("GRANT UPDATE (acknowledgement_note) ON execbound.monitor_findings TO execbound_app")
    op.execute(
        "CREATE INDEX monitor_findings_open ON execbound.monitor_findings "
        "(tenant_id, created_at DESC) WHERE acknowledged_at IS NULL"
    )
    op.execute(ONCE)
    op.execute(f"REVOKE ALL ON FUNCTION {SIGNATURE} FROM PUBLIC")
    for role in SUPABASE_ROLES:
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION {SIGNATURE} FROM {role}")
    op.execute(
        "CREATE TRIGGER monitor_findings_acknowledged_once BEFORE UPDATE OF "
        "acknowledged_at, acknowledged_by, acknowledgement_note "
        "ON execbound.monitor_findings FOR EACH ROW "
        f"EXECUTE FUNCTION {SIGNATURE}"
    )


def downgrade() -> None:
    op.execute("LOCK TABLE execbound.monitor_findings IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE execbound.monitor_findings NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    kept = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_findings "
                "WHERE acknowledgement_note IS NOT NULL)"
            )
        )
        .scalar_one()
    )
    if kept:
        raise RuntimeError("Cannot downgrade while acknowledgement notes are retained")
    op.execute("DROP TRIGGER monitor_findings_acknowledged_once ON execbound.monitor_findings")
    op.execute(f"DROP FUNCTION {SIGNATURE}")
    op.execute("DROP INDEX execbound.monitor_findings_open")
    op.execute("""
        ALTER TABLE execbound.monitor_findings
            DROP CONSTRAINT monitor_findings_note_acknowledged,
            DROP CONSTRAINT monitor_findings_note_length,
            DROP COLUMN acknowledgement_note
    """)
    op.execute("ALTER TABLE execbound.monitor_findings FORCE ROW LEVEL SECURITY")
