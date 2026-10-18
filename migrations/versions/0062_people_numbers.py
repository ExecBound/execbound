"""Counting numbers for people, beside the agents' own.

A person reads "User 3" instead of the first characters of a UUID, the way 0058 gave agents
"Agent 3". Administrators and approvers count upward per workspace in the order they were
created, on a counter separate from agents', so one workspace has a User 1 and an Agent 1. The
numbers are display handles only: every reference, authorization and audit record keeps the
UUID, and a principal a re-invitation replaced (0061) keeps the number it had.

0058's single unique index over `(tenant_id, number)` becomes two partial ones, one per class,
and its check that only an agent has a number becomes `NOT NULL`: every principal has one now.
`number_agent()` is replaced by `number_principal()`, which numbers both classes under an
advisory lock keyed per tenant and class. A change between the two person kinds keeps the
number; a change between a person and an agent drops the old class's number and takes the
next of the new one, which is 0058's rule for agents applied to both classes.

Existing people are numbered by `created_at` (a row from before creation times were kept
comes first), then by principal id, under lifted row-level security as 0058 numbered agents:
the hosted owner does not bypass it, and an unfenced UPDATE would touch nothing. The downgrade
clears people's numbers and restores 0058's index, check, trigger and function, the function
from 0058's own text so it comes back byte for byte.
"""

import importlib.util
from pathlib import Path
from types import ModuleType

from alembic import op

revision = "0062_people_numbers"
down_revision = "0061_replaced_principals"
branch_labels = None
depends_on = None

PERSON = "kind IN ('ADMIN', 'HUMAN_APPROVER')"
LOCK = "LOCK TABLE execbound.principals IN ACCESS EXCLUSIVE MODE"

# One writer per workspace and class takes the next number: a transaction-scoped advisory lock
# keyed on the tenant and the class serialises two concurrent inserts of the same class, and
# each class's unique index refuses anything that slipped past it rather than numbering two
# rows alike. The agents' key is 0058's, so an insert under either revision waits on the same
# lock. The function runs as the inserting role inside its tenant fence, which is how every
# principal is written. An INSERT that names a number keeps it, as under 0058; a change of kind
# across the two classes always takes a fresh one.
NUMBER_PRINCIPAL = f"""
CREATE FUNCTION execbound.number_principal() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.kind = 'AGENT') <> (OLD.kind = 'AGENT') THEN
        NEW.number := NULL;
    END IF;
    IF NEW.number IS NULL AND NEW.kind = 'AGENT' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended('execbound.agent_number:' || NEW.tenant_id::text, 0));
        SELECT coalesce(max(p.number), 0) + 1 INTO NEW.number
        FROM execbound.principals p
        WHERE p.tenant_id = NEW.tenant_id AND p.kind = 'AGENT';
    ELSIF NEW.number IS NULL AND NEW.{PERSON} THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended('execbound.person_number:' || NEW.tenant_id::text, 0));
        SELECT coalesce(max(p.number), 0) + 1 INTO NEW.number
        FROM execbound.principals p
        WHERE p.tenant_id = NEW.tenant_id AND p.{PERSON};
    END IF;
    RETURN NEW;
END $$
"""


def _numbers_0058() -> ModuleType:
    """0058's module, for the text of the function and index this revision replaces."""
    spec = importlib.util.spec_from_file_location(
        "api_key_numbers", Path(__file__).with_name("0058_api_key_numbers.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _lock() -> None:
    # The strongest lock first. `DROP TRIGGER` takes SHARE ROW EXCLUSIVE and only a later
    # statement upgrades it, so on hosted, where the services keep running during an apply, a
    # live transaction holding ACCESS SHARE on `principals` and then writing to it could
    # deadlock with the migration. Taken first, the migration simply waits its turn.
    op.execute(LOCK)


def _lift_rls() -> None:
    # 0058's bracket, on the one table this revision numbers: an exclusive lock, FORCE lifted
    # so the owner reads every tenant's rows, and `row_security = off` so a policy that still
    # applied would raise rather than quietly filter.
    op.execute(LOCK)
    op.execute("ALTER TABLE execbound.principals NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")


def _restore_rls() -> None:
    op.execute("ALTER TABLE execbound.principals FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def upgrade() -> None:
    _lock()
    op.execute("DROP TRIGGER principals_number ON execbound.principals")
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_number_kind")
    # A person's first number collides with an agent's under the shared index.
    op.execute("DROP INDEX execbound.principals_number")
    _lift_rls()
    op.execute(f"""
        UPDATE execbound.principals p SET number = n.number
        FROM (SELECT tenant_id, principal_id, row_number() OVER (
                  PARTITION BY tenant_id ORDER BY created_at NULLS FIRST, principal_id) AS number
              FROM execbound.principals WHERE {PERSON}) n
        WHERE p.tenant_id = n.tenant_id AND p.principal_id = n.principal_id
    """)
    _restore_rls()
    # A backfill that touched nothing leaves a person without a number, and this refuses it.
    op.execute("ALTER TABLE execbound.principals ALTER COLUMN number SET NOT NULL")
    op.execute(
        "CREATE UNIQUE INDEX principals_agent_number ON execbound.principals "
        "(tenant_id, number) WHERE kind = 'AGENT'"
    )
    op.execute(
        "CREATE UNIQUE INDEX principals_person_number ON execbound.principals "
        f"(tenant_id, number) WHERE {PERSON}"
    )
    op.execute(NUMBER_PRINCIPAL)
    op.execute("REVOKE ALL ON FUNCTION execbound.number_principal() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER principals_number BEFORE INSERT OR UPDATE OF kind "
        "ON execbound.principals "
        "FOR EACH ROW EXECUTE FUNCTION execbound.number_principal()"
    )
    op.execute("DROP FUNCTION execbound.number_agent()")


def downgrade() -> None:
    _lock()
    old = _numbers_0058()
    op.execute("DROP TRIGGER principals_number ON execbound.principals")
    op.execute("ALTER TABLE execbound.principals ALTER COLUMN number DROP NOT NULL")
    op.execute("DROP INDEX execbound.principals_person_number")
    op.execute("DROP INDEX execbound.principals_agent_number")
    _lift_rls()
    op.execute(f"UPDATE execbound.principals SET number = NULL WHERE {PERSON}")
    _restore_rls()
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_number_kind "
        "CHECK ((kind = 'AGENT') = (number IS NOT NULL))"
    )
    op.execute(
        "CREATE UNIQUE INDEX principals_number ON execbound.principals (tenant_id, number) "
        "WHERE number IS NOT NULL"
    )
    op.execute(old.NUMBER_AGENT)
    op.execute("REVOKE ALL ON FUNCTION execbound.number_agent() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER principals_number BEFORE INSERT OR UPDATE OF kind "
        "ON execbound.principals "
        "FOR EACH ROW EXECUTE FUNCTION execbound.number_agent()"
    )
    op.execute("DROP FUNCTION execbound.number_principal()")
