"""An agent's API key may be issued with no expiry: the one far-future instant `NEVER`."""

from alembic import op
from sqlalchemy import text

revision = "0057_api_key_never"
down_revision = "0056_gate_evidence"
branch_labels = None
depends_on = None

# `identity.NEVER`, spelled for the database. A key that never expires still carries a real
# expiry, so every reader that compares or takes a minimum of it (authentication, admission,
# the replay capture) keeps working unchanged; only this exact instant is allowed past the cap,
# and only for an agent. Anything else past 90 days stays `INVALID_LIFETIME`.
NEVER = "timestamptz '9999-12-31 00:00:00+00'"
CAPPED = "       OR p_expires_at - p_issued_at > interval '90 days' THEN"
UNCAPPED = (
    "       OR (p_expires_at - p_issued_at > interval '90 days'\n"
    f"           AND NOT (v_kind = 'AGENT' AND p_expires_at = {NEVER})) THEN"
)


def _replace(before: str, after: str) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = 'admin_issue_credential'"
        )
    ).scalar_one()
    # Exactly one lifetime check exists; a definition that no longer carries it verbatim has
    # been changed by something this migration does not know, and is refused, not guessed at.
    if definition.count(before) != 1:
        raise RuntimeError("admin_issue_credential no longer has the expected lifetime check")
    # CREATE OR REPLACE keeps the function's owner, its SECURITY DEFINER and its grants. The
    # body goes straight to the driver: `text()` would read its `:=` and casts as parameters.
    conn.exec_driver_sql(definition.replace(before, after))


def upgrade() -> None:
    _replace(CAPPED, UNCAPPED)


def downgrade() -> None:
    # Keys already issued with no expiry keep it: authentication only compares the expiry,
    # so the previous code accepts them, and revoking one is the way to end it.
    _replace(UNCAPPED, CAPPED)
