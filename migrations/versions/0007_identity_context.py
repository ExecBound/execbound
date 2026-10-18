"""Read-only identity privilege evidence and bounded identity action storage."""

from alembic import op
from sqlalchemy import text

revision = "0007_identity_context"
down_revision = "0006_human_sessions"
branch_labels = None
depends_on = None

# Applied history is independent of the current application's operation catalog.
ACTIONS = "'endpoint.isolate', 'identity.disable', 'identity.enable', 'identity.revoke_sessions'"
ACTION_TABLES = ("approval_scopes", "execution_impact")
HISTORY_TABLES = (
    "connector_accounts",
    "operation_mappings",
    "resources",
    "approval_scopes",
    "execution_impact",
    "executions",
    "execution_events",
    "policy_bundle_contents",
    "audit_events",
)


def upgrade() -> None:
    # A nullable field preserves every existing endpoint row. Existing SELECT-only
    # inventory grants automatically cover the column; no write grant is added.
    op.execute("""
        ALTER TABLE execbound.resources ADD COLUMN privilege_class text
        CONSTRAINT resources_privilege_class_check
        CHECK (privilege_class IN ('standard', 'privileged', 'tier0'))
    """)
    for table in ACTION_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} DROP CONSTRAINT {table}_action_check")
        op.execute(
            f"ALTER TABLE execbound.{table} ADD CONSTRAINT {table}_action_check "
            f"CHECK (action IN ({ACTIONS}))"
        )


def downgrade() -> None:
    # FORCE RLS also filters a non-bypass migration owner. Acquire all locks first
    # so no runtime reader/writer can observe or exploit the temporary owner-only
    # inspection. PostgreSQL transaction rollback restores FORCE on any refusal.
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"execbound.{table}" for table in HISTORY_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in HISTORY_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    # Never silently accept a filtered inspection if the migration is executed by
    # an unexpected role. This does not bypass RLS; it raises if RLS would apply.
    op.execute("SET LOCAL row_security = off")
    predicates = {
        "connector_accounts": "provider = 'mock_entra'",
        "operation_mappings": (
            "provider = 'mock_entra' OR resource_type = 'identity' "
            "OR action LIKE 'identity.%' OR context_contract_version = 'identity-control.v1'"
        ),
        "resources": (
            "privilege_class IS NOT NULL OR provider = 'mock_entra' OR resource_type = 'identity'"
        ),
        "approval_scopes": "action <> 'endpoint.isolate'",
        "execution_impact": "action <> 'endpoint.isolate'",
    }
    # Retained JSON evidence can outlive inventory or active mappings, including
    # retired policy content and terminal results. Conservative refusal is safer
    # than discarding an identity record whose current projection was removed.
    evidence_pattern = (
        r"mock_entra|identity[.]|identity-control[.]v1|privilege_class|"
        r'"resource_type"[[:space:]]*:[[:space:]]*"identity"'
    )
    json_columns = {
        "executions": ("frozen", "result"),
        "execution_events": ("payload",),
        "policy_bundle_contents": ("content",),
        "audit_events": ("payload",),
    }
    for table in HISTORY_TABLES:
        if table in predicates:
            predicate = predicates[table]
            params = {}
        else:
            predicate = " OR ".join(f"{column}::text ~ :pattern" for column in json_columns[table])
            if table == "audit_events":
                predicate += " OR kind LIKE 'identity.%'"
            params = {"pattern": evidence_pattern}
        if (
            op.get_bind()
            .execute(
                text(f"SELECT EXISTS (SELECT 1 FROM execbound.{table} WHERE {predicate})"), params
            )
            .scalar_one()
        ):
            raise RuntimeError("Cannot downgrade while identity data or history is retained")
    for table in HISTORY_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    for table in ACTION_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} DROP CONSTRAINT {table}_action_check")
        op.execute(
            f"ALTER TABLE execbound.{table} ADD CONSTRAINT {table}_action_check "
            "CHECK (action = 'endpoint.isolate')"
        )
    op.execute("ALTER TABLE execbound.resources DROP COLUMN privilege_class")
