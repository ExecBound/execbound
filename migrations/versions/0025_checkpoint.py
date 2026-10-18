"""External execution checkpoint: executor keys, the settlement tier and the report window."""

from alembic import op
from sqlalchemy import text

revision = "0025_checkpoint"
down_revision = "0024_monitor_rls_initplan"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
# The downgrade guard reads every tenant's keys and settled executions, so RLS is lifted on
# the tables it reads for the transaction and restored before it ends.
INSPECTED = ("executor_keys", "executions")
# A named key so a rotation keeps an outstanding proof verifiable, and the executor's raw
# 32-byte Ed25519 public key in hex: nothing secret is stored, so read-only access to this
# table cannot forge the attested tier.
KEY_ID = "^[a-zA-Z0-9_.-]{1,64}$"
PUBLIC_KEY = "^[0-9a-f]{64}$"


def _lift_rls(tables: tuple[str, ...]) -> None:
    op.execute(
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in tables) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")


def _restore_rls(tables: tuple[str, ...]) -> None:
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def _protect(table: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.{table}
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
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
    # Executor keys are owner-provisioned authority data like approval scopes and principal
    # groups: the runtime verifies an executor's record with them and never writes one.
    op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE execbound.executor_keys (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            key_id text NOT NULL CHECK (key_id ~ '{KEY_ID}'),
            public_key text NOT NULL CHECK (public_key ~ '{PUBLIC_KEY}'),
            created_at timestamptz NOT NULL,
            revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            PRIMARY KEY (tenant_id, key_id)
        )
    """)
    _protect("executor_keys")
    # A tier is null until a report settles the execution; a report window is null except on
    # a checkpoint, where admission writes it once and nothing updates it afterwards.
    op.execute("""
        ALTER TABLE execbound.executions
            ADD COLUMN settlement_tier text CHECK (settlement_tier IN ('ATTESTED', 'ASSERTED')),
            ADD COLUMN report_expires_at timestamptz
    """)
    op.execute("GRANT UPDATE (settlement_tier) ON execbound.executions TO execbound_app")


def downgrade() -> None:
    # A registered executor key, a settled tier and an open report window have no
    # representation in 0022, and dropping either column would discard settlement evidence.
    _lift_rls(INSPECTED)
    bind = op.get_bind()
    predicates = {
        "executor_keys": "true",
        "executions": "settlement_tier IS NOT NULL OR report_expires_at IS NOT NULL",
    }
    for table, predicate in predicates.items():
        retained = bind.execute(
            text(f"SELECT EXISTS (SELECT 1 FROM execbound.{table} WHERE {predicate})")
        )
        if retained.scalar_one():
            raise RuntimeError("Cannot downgrade while executor keys or checkpoints exist")
    _restore_rls(INSPECTED)
    op.execute(
        "ALTER TABLE execbound.executions "
        "DROP COLUMN report_expires_at, DROP COLUMN settlement_tier"
    )
    op.execute("DROP TABLE execbound.executor_keys")
