"""Read-only generic resource facts for versioned context contracts."""

from alembic import op
from sqlalchemy import text

revision = "0009_context_contracts"
down_revision = "0008_monitoring"
branch_labels = None
depends_on = None

V1_CONTRACTS = "'endpoint-isolation.v1', 'identity-control.v1'"
# SQL/JSON path filter selecting a stored contract version outside the v1 catalog.
NON_V1 = '? (@ != "endpoint-isolation.v1" && @ != "identity-control.v1")'
HISTORY_TABLES = (
    "resource_facts",
    "operation_mappings",
    "policy_bundle_contents",
    "executions",
    "execution_events",
    "audit_events",
)


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.resource_facts (
            tenant_id uuid NOT NULL,
            account_id uuid NOT NULL,
            provider text NOT NULL,
            resource_type text NOT NULL,
            resource_id uuid NOT NULL,
            fact_name text NOT NULL CHECK (fact_name ~ '^[a-z][a-z0-9_]{0,62}$'),
            value jsonb NOT NULL CHECK (
                (jsonb_typeof(value) = 'string' AND length(value #>> '{}') BETWEEN 1 AND 254)
                OR jsonb_typeof(value) = 'boolean'
                OR (jsonb_typeof(value) = 'number' AND value::text ~ '^-?[0-9]{1,18}$')
            ),
            source_id uuid NOT NULL,
            version text NOT NULL CHECK (length(version) BETWEEN 1 AND 80),
            observed_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, account_id, provider, resource_type, resource_id, fact_name),
            FOREIGN KEY (tenant_id, account_id, provider, resource_type, resource_id)
                REFERENCES execbound.resources,
            FOREIGN KEY (tenant_id, account_id, source_id) REFERENCES execbound.context_sources
        )
    """)
    op.execute(
        "CREATE INDEX resource_facts_source "
        "ON execbound.resource_facts (tenant_id, account_id, source_id)"
    )
    op.execute("ALTER TABLE execbound.resource_facts ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.resource_facts FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation ON execbound.resource_facts
        USING (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
        WITH CHECK (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
    """)
    for role in ("PUBLIC", "anon", "authenticated", "service_role", "execbound_app"):
        if (
            role != "PUBLIC"
            and not op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            continue
        op.execute(f"REVOKE ALL ON execbound.resource_facts FROM {role}")
    op.execute("GRANT SELECT ON execbound.resource_facts TO execbound_app")


def downgrade() -> None:
    # Follow 0007: lock, inspect every tenant without RLS filtering, then refuse to
    # discard facts, non-v1 mappings, bundles with settings, or any bundle, frozen plan
    # or retained execution/audit evidence naming a non-v1 contract. Revision 0007
    # cannot parse that content, including a DRAFT bundle that was never validated.
    retained_evidence = f"jsonb_path_exists(payload, '$.**.context_contract_version {NON_V1}')"
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"execbound.{table}" for table in HISTORY_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in HISTORY_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    predicates = {
        "resource_facts": "true",
        "operation_mappings": f"context_contract_version NOT IN ({V1_CONTRACTS})",
        "policy_bundle_contents": (
            "jsonb_exists(content, 'context_settings') OR "
            f"jsonb_path_exists(content, '$.mappings[*].context_contract_version {NON_V1}')"
        ),
        "executions": f"(frozen ->> 'context_contract_version') NOT IN ({V1_CONTRACTS})",
        "execution_events": retained_evidence,
        "audit_events": retained_evidence,
    }
    for table, predicate in predicates.items():
        retained = op.get_bind().execute(
            text(f"SELECT EXISTS (SELECT 1 FROM execbound.{table} WHERE {predicate})")
        )
        if retained.scalar_one():
            raise RuntimeError(
                "Cannot downgrade while context contract data or history is retained"
            )
    for table in HISTORY_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("DROP TABLE execbound.resource_facts")
