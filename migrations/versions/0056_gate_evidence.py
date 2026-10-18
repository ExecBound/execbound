"""Tines Gate evidence: an executor key's algorithm, and the provider-verified tier."""

from alembic import op
from sqlalchemy import text

revision = "0056_gate_evidence"
down_revision = "0055_community_signup"
branch_labels = None
depends_on = None

# The downgrade guard reads every tenant's rows, so row-level security is lifted on these
# tables around it and restored before the transaction ends, following 0025 and 0026. The
# upgrade needs no lift: ADD COLUMN with a default fills every existing row whatever the
# session's row-level security says, and ADD CONSTRAINT validates every row the same way.
INSPECTED = ("executor_keys", "executions")
ED25519_KEY = "^[0-9a-f]{64}$"
ES256_KEY = "^0[23][0-9a-f]{64}$"
KEY_SHAPE = (
    f"(algorithm = 'ED25519' AND public_key ~ '{ED25519_KEY}') OR "
    f"(algorithm = 'ES256' AND public_key ~ '{ES256_KEY}')"
)
TIERS_AFTER = "settlement_tier IN ('ATTESTED', 'ASSERTED', 'PROVIDER_VERIFIED')"
TIERS_BEFORE = "settlement_tier IN ('ATTESTED', 'ASSERTED')"


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


def upgrade() -> None:
    # Every key that exists is Ed25519: nothing could register another kind before this.
    # The default fills them and is then dropped, so every later insert names its algorithm.
    op.execute(
        "ALTER TABLE execbound.executor_keys ADD COLUMN algorithm text NOT NULL DEFAULT 'ED25519'"
    )
    op.execute("ALTER TABLE execbound.executor_keys ALTER COLUMN algorithm DROP DEFAULT")
    op.execute("ALTER TABLE execbound.executor_keys DROP CONSTRAINT executor_keys_public_key_check")
    op.execute(
        f"ALTER TABLE execbound.executor_keys ADD CONSTRAINT executor_keys_public_key "
        f"CHECK ({KEY_SHAPE})"
    )
    op.execute("ALTER TABLE execbound.executions DROP CONSTRAINT executions_settlement_tier_check")
    op.execute(
        f"ALTER TABLE execbound.executions ADD CONSTRAINT executions_settlement_tier "
        f"CHECK ({TIERS_AFTER})"
    )
    # The runtime's SELECT on executor_keys covers the new column, and its UPDATE on
    # settlement_tier is unchanged, so no grant moves.


def downgrade() -> None:
    # An ES256 key and a provider-verified settlement have no representation in 0055, and
    # dropping either would discard what a settled grant was verified against.
    _lift_rls(INSPECTED)
    bind = op.get_bind()
    for table, predicate in (
        ("executor_keys", "algorithm <> 'ED25519'"),
        ("executions", "settlement_tier = 'PROVIDER_VERIFIED'"),
    ):
        retained = bind.execute(
            text(f"SELECT EXISTS (SELECT 1 FROM execbound.{table} WHERE {predicate})")
        )
        if retained.scalar_one():
            raise RuntimeError("Cannot downgrade while ES256 keys or provider settlements exist")
    _restore_rls(INSPECTED)
    op.execute("ALTER TABLE execbound.executions DROP CONSTRAINT executions_settlement_tier")
    op.execute(
        f"ALTER TABLE execbound.executions ADD CONSTRAINT executions_settlement_tier_check "
        f"CHECK ({TIERS_BEFORE})"
    )
    op.execute("ALTER TABLE execbound.executor_keys DROP CONSTRAINT executor_keys_public_key")
    op.execute(
        f"ALTER TABLE execbound.executor_keys ADD CONSTRAINT executor_keys_public_key_check "
        f"CHECK (public_key ~ '{ED25519_KEY}')"
    )
    op.execute("ALTER TABLE execbound.executor_keys DROP COLUMN algorithm")
