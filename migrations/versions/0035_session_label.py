"""A device label on a human session, decided from the browser's User-Agent at sign-in.

The label is one of a small fixed set of strings ("Chrome on Windows", "Safari on iPhone",
"Other") chosen by the application; the header itself is never stored. It is written with
the row and never updated, so the runtime's existing table-level INSERT grant and its
`revoked_at`-only UPDATE grant on `human_sessions` are unchanged, and `check_runtime` sees no
new column privilege.
"""

from alembic import op

revision = "0035_session_label"
down_revision = "0034_agent_owner_org"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.human_sessions ADD COLUMN label text "
        "CHECK (label IS NULL OR char_length(label) BETWEEN 1 AND 80)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE execbound.human_sessions DROP COLUMN label")
