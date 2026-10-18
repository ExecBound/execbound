"""Store the full signed 64-bit Long range in resource_facts, matching the fact domain."""

from alembic import op
from sqlalchemy import text

revision = "0020_resource_facts_long"
down_revision = "0019_observe_mode"
branch_labels = None
depends_on = None

STRING_OR_BOOLEAN = (
    "(jsonb_typeof(value) = 'string' AND length(value #>> '{}') BETWEEN 1 AND 254) "
    "OR jsonb_typeof(value) = 'boolean'"
)
# Cedar Long is a signed 64-bit integer; jsonb keeps numbers exact, so the range check
# is precise and the pattern keeps out fractions and exponents.
LONG = (
    "(jsonb_typeof(value) = 'number' AND value::text ~ '^-?[0-9]{1,19}$' "
    "AND (value #>> '{}')::numeric BETWEEN -9223372036854775808 AND 9223372036854775807)"
)
LEGACY = "(jsonb_typeof(value) = 'number' AND value::text ~ '^-?[0-9]{1,18}$')"


def _value_check(number_rule: str) -> None:
    op.execute("ALTER TABLE execbound.resource_facts DROP CONSTRAINT resource_facts_value_check")
    op.execute(
        "ALTER TABLE execbound.resource_facts ADD CONSTRAINT resource_facts_value_check "
        f"CHECK ({STRING_OR_BOOLEAN} OR {number_rule})"
    )


def upgrade() -> None:
    _value_check(LONG)


def downgrade() -> None:
    # A retained 19-digit fact could not satisfy the narrower legacy check: refuse.
    op.execute("ALTER TABLE execbound.resource_facts NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = op.get_bind().execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.resource_facts "
            "WHERE jsonb_typeof(value) = 'number' AND value::text !~ '^-?[0-9]{1,18}$')"
        )
    )
    if retained.scalar_one():
        raise RuntimeError("Cannot downgrade while resource facts beyond 18 digits are retained")
    _value_check(LEGACY)
    op.execute("ALTER TABLE execbound.resource_facts FORCE ROW LEVEL SECURITY")
