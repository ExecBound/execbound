"""Durable execution claims, scoped approvals and retained target impact."""

from alembic import op
from sqlalchemy import text

revision = "0005_execution_state"
down_revision = "0004_policy_bundles"
branch_labels = None
depends_on = None

TABLES = (
    "canonical_targets",
    "resource_identities",
    "approval_scopes",
    "executions",
    "execution_keys",
    "execution_events",
    "approvals",
    "execution_impact",
    "resource_claims",
)
EXECUTION_STATES = (
    "'ATTEMPTED', 'DENIED', 'PENDING_APPROVAL', 'RESERVED', 'DISPATCH_COMMITTED', "
    "'EXECUTED', 'FAILED_NOT_EXECUTED', 'INDETERMINATE', 'STALE_AUTHORIZATION'"
)


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.canonical_targets (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            canonical_target_id uuid NOT NULL,
            created_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, canonical_target_id)
        )
    """)
    op.execute("""
        CREATE TABLE execbound.resource_identities (
            tenant_id uuid NOT NULL,
            account_id uuid NOT NULL,
            provider text NOT NULL,
            resource_type text NOT NULL,
            resource_id uuid NOT NULL,
            canonical_target_id uuid NOT NULL,
            PRIMARY KEY (tenant_id, account_id, provider, resource_type, resource_id),
            FOREIGN KEY (tenant_id, account_id, provider, resource_type, resource_id)
                REFERENCES execbound.resources,
            FOREIGN KEY (tenant_id, canonical_target_id) REFERENCES execbound.canonical_targets
        )
    """)
    op.execute(
        "CREATE INDEX resource_identities_target "
        "ON execbound.resource_identities (tenant_id, canonical_target_id)"
    )
    op.execute("""
        CREATE TABLE execbound.approval_scopes (
            tenant_id uuid NOT NULL,
            approver_id uuid NOT NULL,
            canonical_target_id uuid NOT NULL,
            action text NOT NULL CHECK (action = 'endpoint.isolate'),
            active boolean NOT NULL DEFAULT true,
            PRIMARY KEY (tenant_id, approver_id, canonical_target_id, action),
            FOREIGN KEY (tenant_id, approver_id) REFERENCES execbound.principals,
            FOREIGN KEY (tenant_id, canonical_target_id) REFERENCES execbound.canonical_targets
        )
    """)
    op.execute(
        "CREATE INDEX approval_scopes_target "
        "ON execbound.approval_scopes (tenant_id, canonical_target_id)"
    )
    op.execute(f"""
        CREATE TABLE execbound.executions (
            tenant_id uuid NOT NULL,
            execution_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            credential_id uuid NOT NULL,
            intent_hash text NOT NULL CHECK (intent_hash ~ '^[0-9a-f]{{64}}$'),
            wire_hash text NOT NULL CHECK (wire_hash ~ '^[0-9a-f]{{64}}$'),
            plan_hash text NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{{64}}$'),
            canonical_target_id uuid NOT NULL,
            bundle_id uuid NOT NULL,
            frozen jsonb NOT NULL CHECK (jsonb_typeof(frozen) = 'object'),
            state text NOT NULL CHECK (state IN ({EXECUTION_STATES})),
            created_at timestamptz NOT NULL,
            changed_at timestamptz NOT NULL,
            operation_id uuid NOT NULL,
            owner_hash text CHECK (owner_hash ~ '^[0-9a-f]{{64}}$'),
            dispatch_attempted_at timestamptz,
            result jsonb,
            PRIMARY KEY (tenant_id, execution_id),
            UNIQUE (tenant_id, principal_id, execution_id),
            UNIQUE (tenant_id, operation_id),
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
            FOREIGN KEY (tenant_id, credential_id) REFERENCES execbound.credentials,
            FOREIGN KEY (tenant_id, canonical_target_id) REFERENCES execbound.canonical_targets,
            FOREIGN KEY (tenant_id, bundle_id) REFERENCES execbound.policy_bundle_contents
        )
    """)
    op.execute(
        "CREATE UNIQUE INDEX executions_unresolved_intent "
        "ON execbound.executions (tenant_id, principal_id, intent_hash) "
        "WHERE state IN ('ATTEMPTED', 'PENDING_APPROVAL', 'RESERVED', "
        "'DISPATCH_COMMITTED', 'INDETERMINATE')"
    )
    for name, columns in (
        ("credential", "tenant_id, credential_id"),
        ("target", "tenant_id, canonical_target_id"),
        ("bundle", "tenant_id, bundle_id"),
    ):
        op.execute(f"CREATE INDEX executions_{name} ON execbound.executions ({columns})")
    op.execute("""
        CREATE TABLE execbound.execution_keys (
            tenant_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
            intent_hash text NOT NULL CHECK (intent_hash ~ '^[0-9a-f]{64}$'),
            wire_hash text NOT NULL CHECK (wire_hash ~ '^[0-9a-f]{64}$'),
            execution_id uuid NOT NULL,
            PRIMARY KEY (tenant_id, principal_id, idempotency_key),
            FOREIGN KEY (tenant_id, principal_id, execution_id)
                REFERENCES execbound.executions(tenant_id, principal_id, execution_id)
        )
    """)
    op.execute(
        "CREATE INDEX execution_keys_execution "
        "ON execbound.execution_keys (tenant_id, principal_id, execution_id)"
    )
    op.execute(f"""
        CREATE TABLE execbound.execution_events (
            tenant_id uuid NOT NULL,
            event_id uuid NOT NULL,
            execution_id uuid NOT NULL,
            actor_id uuid NOT NULL,
            from_state text CHECK (from_state IN ({EXECUTION_STATES})),
            to_state text NOT NULL CHECK (to_state IN ({EXECUTION_STATES})),
            created_at timestamptz NOT NULL,
            payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
            PRIMARY KEY (tenant_id, event_id),
            FOREIGN KEY (tenant_id, execution_id) REFERENCES execbound.executions,
            FOREIGN KEY (tenant_id, actor_id) REFERENCES execbound.principals
        )
    """)
    op.execute(
        "CREATE INDEX execution_events_execution "
        "ON execbound.execution_events (tenant_id, execution_id, created_at)"
    )
    op.execute(
        "CREATE INDEX execution_events_actor ON execbound.execution_events (tenant_id, actor_id)"
    )
    op.execute("""
        CREATE TABLE execbound.approvals (
            tenant_id uuid NOT NULL,
            approval_id uuid NOT NULL,
            execution_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            plan_hash text NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
            bundle_id uuid NOT NULL,
            obligation_ids jsonb NOT NULL CHECK (jsonb_typeof(obligation_ids) = 'array'),
            expires_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL,
            state text NOT NULL CHECK (state IN (
                'PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'INVALIDATED', 'CONSUMED'
            )),
            decided_by uuid,
            decided_credential_id uuid,
            decided_at timestamptz,
            PRIMARY KEY (tenant_id, approval_id),
            UNIQUE (tenant_id, execution_id),
            FOREIGN KEY (tenant_id, execution_id) REFERENCES execbound.executions,
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
            FOREIGN KEY (tenant_id, bundle_id) REFERENCES execbound.policy_bundle_contents,
            FOREIGN KEY (tenant_id, decided_by) REFERENCES execbound.principals,
            FOREIGN KEY (tenant_id, decided_credential_id) REFERENCES execbound.credentials
        )
    """)
    for name, columns in (
        ("principal", "tenant_id, principal_id"),
        ("bundle", "tenant_id, bundle_id"),
        ("decider", "tenant_id, decided_by"),
        ("credential", "tenant_id, decided_credential_id"),
    ):
        op.execute(f"CREATE INDEX approvals_{name} ON execbound.approvals ({columns})")
    op.execute("""
        CREATE TABLE execbound.execution_impact (
            tenant_id uuid NOT NULL,
            execution_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            action text NOT NULL CHECK (action = 'endpoint.isolate'),
            approved boolean NOT NULL,
            state text NOT NULL CHECK (state IN ('UNRESOLVED', 'CONFIRMED', 'NONEXECUTION')),
            confirmed_at timestamptz,
            created_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, execution_id),
            CHECK ((state = 'CONFIRMED') = (confirmed_at IS NOT NULL)),
            FOREIGN KEY (tenant_id, execution_id) REFERENCES execbound.executions,
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals
        )
    """)
    op.execute(
        "CREATE INDEX execution_impact_principal "
        "ON execbound.execution_impact (tenant_id, principal_id, action, state, confirmed_at)"
    )
    op.execute(
        "CREATE INDEX execution_impact_tenant "
        "ON execbound.execution_impact (tenant_id, action, state, confirmed_at)"
    )
    op.execute("""
        CREATE TABLE execbound.resource_claims (
            tenant_id uuid NOT NULL,
            execution_id uuid NOT NULL,
            canonical_target_id uuid NOT NULL,
            released_at timestamptz,
            PRIMARY KEY (tenant_id, execution_id),
            FOREIGN KEY (tenant_id, execution_id) REFERENCES execbound.executions,
            FOREIGN KEY (tenant_id, canonical_target_id) REFERENCES execbound.canonical_targets
        )
    """)
    op.execute(
        "CREATE INDEX resource_claims_target "
        "ON execbound.resource_claims (tenant_id, canonical_target_id)"
    )
    op.execute(
        "CREATE UNIQUE INDEX resource_claims_unresolved_target "
        "ON execbound.resource_claims (tenant_id, canonical_target_id) WHERE released_at IS NULL"
    )
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON execbound.{table}
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
            op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
        op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")
        if table not in {"canonical_targets", "resource_identities", "approval_scopes"}:
            op.execute(f"GRANT INSERT ON execbound.{table} TO execbound_app")
    for table, columns in (
        ("executions", "state, changed_at, owner_hash, dispatch_attempted_at, result"),
        ("approvals", "state, decided_by, decided_credential_id, decided_at"),
        ("execution_impact", "state, confirmed_at"),
        ("resource_claims", "released_at"),
    ):
        op.execute(f"GRANT UPDATE ({columns}) ON execbound.{table} TO execbound_app")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
