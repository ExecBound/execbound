"""The organization that owns an external agent's application, so sponsorship can be scoped."""

from alembic import op
from sqlalchemy import text

revision = "0034_agent_owner_org"
down_revision = "0033_reported_failure"
branch_labels = None
depends_on = None

GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


def upgrade() -> None:
    # Null means the application was registered in this directory, which is how a locally
    # created agent identity appears; a value naming another organization means the customer
    # did not create it and cannot meaningfully be asked to sponsor it.
    op.execute(f"""
        ALTER TABLE execbound.monitor_agents
            ADD COLUMN owner_org_ref text CHECK (owner_org_ref ~ '{GUID}')
    """)
    op.execute("GRANT UPDATE (owner_org_ref) ON execbound.monitor_agents TO execbound_app")


def downgrade() -> None:
    op.execute("ALTER TABLE execbound.monitor_agents NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    if (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_agents "
                "WHERE owner_org_ref IS NOT NULL)"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError("Cannot downgrade while an agent records its owning organization")
    op.execute("ALTER TABLE execbound.monitor_agents FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.monitor_agents DROP COLUMN owner_org_ref")
