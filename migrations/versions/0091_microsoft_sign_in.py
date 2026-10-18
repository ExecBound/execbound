# SPDX-License-Identifier: AGPL-3.0-only
"""Microsoft joins the deployment's sign-in providers (#678).

A deployment may now offer Microsoft work accounts beside Google and GitHub. What a Microsoft
sign-in stores is what the other two store: a `user_identities` binding, a login proof and an
account session with its method, a pending provider link, and, where a plugin offers signup
through a provider, the request's completing provider. So this revision widens the five column
checks that list the providers or the methods, and the two definer functions that refuse a
provider or method they do not know:

- `user_identities.provider`, `account_login_proofs.method`, `account_sessions.method`,
  `account_provider_links.provider` and `signup_requests.completion_provider` gain
  `'microsoft'`. Each check is found in the catalog by its table and column (exactly one match,
  or the revision refuses), dropped and added again under its own name.
- `sign_in_credential`'s method list and `signup_provider_attach`'s provider list gain
  `'microsoft'`, patched in place as `0070_first_password` patches its function: the live
  definition is read, each fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps
  the owner, `SECURITY DEFINER`, `search_path` and the grants.

`principal_identities.provider` and `identity_sign_in` stay `('google', 'github')`. They hold
only bindings made before accounts existed, which a first sign-in adopts; no Microsoft binding
predates accounts, so there is nothing for them to hold.

No table, function, policy or grant is added and no signature changes. The downgrade refuses
`MICROSOFT_ROWS_PRESENT` while any of the five columns holds `'microsoft'`, looking with row
security off for the look alone, because an owner that does not bypass it would otherwise see
nothing. It runs in a later process with no record of the upgrade, so it derives each earlier
definition from the live one, removing the one `'microsoft'` entry the upgrade added.
"""

from alembic import op
from sqlalchemy import text

revision = "0091_microsoft_sign_in"
down_revision = "0090_monitor_source_creator"
branch_labels = None
depends_on = None

CHECKED = (
    ("user_identities", "provider"),
    ("account_login_proofs", "method"),
    ("account_sessions", "method"),
    ("account_provider_links", "provider"),
    ("signup_requests", "completion_provider"),
)
# As PostgreSQL renders a list check: `CHECK ((provider = ANY (ARRAY['google'::text, ...])))`.
CONSTRAINT_BEFORE = "'github'::text]"
CONSTRAINT_AFTER = "'github'::text, 'microsoft'::text]"
CONSTRAINT_ADDED = ", 'microsoft'::text"
PATCHES = (
    (
        "sign_in_credential",
        "p_method NOT IN ('password', 'google', 'github')",
        "p_method NOT IN ('password', 'google', 'github', 'microsoft')",
    ),
    (
        "signup_provider_attach",
        "p_provider NOT IN ('google', 'github')",
        "p_provider NOT IN ('google', 'github', 'microsoft')",
    ),
)
FUNCTION_ADDED = ", 'microsoft'"


def _constraint(table: str, column: str) -> tuple[str, str]:
    """The one provider or method check on `table.column`, by name and definition."""
    found = (
        op.get_bind()
        .execute(
            text(
                "SELECT c.conname, pg_get_constraintdef(c.oid) FROM pg_constraint c "
                "JOIN pg_class r ON r.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = r.relnamespace "
                "JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = ANY(c.conkey) "
                "WHERE n.nspname = 'execbound' AND r.relname = :t AND a.attname = :c "
                "AND c.contype = 'c' AND pg_get_constraintdef(c.oid) LIKE :g"
            ),
            {"t": table, "c": column, "g": "%'google'::text%"},
        )
        .all()
    )
    # A check that is not there exactly once was changed by something this revision does not
    # know, and is refused rather than guessed at.
    if len(found) != 1:
        raise RuntimeError(f"{table}.{column} has no single provider check {revision} widens")
    name, definition = found[0]
    return str(name), str(definition)


def _recreate(table: str, name: str, definition: str) -> None:
    # Identifiers from the catalog query above, constants of this file; never input.
    op.execute(
        f"ALTER TABLE execbound.{table} DROP CONSTRAINT {name}, "  # nosec B608
        f"ADD CONSTRAINT {name} {definition}"
    )


def _once(definition: str, before: str, after: str, what: str) -> str:
    if definition.count(before) != 1:
        raise RuntimeError(f"{what} no longer has the fragment {revision} changes")
    return definition.replace(before, after)


def _function(name: str) -> str:
    return str(
        op.get_bind()
        .execute(
            text(
                "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = :name"
            ),
            {"name": name},
        )
        .scalar_one()
    )


def _replace(name: str, before: str, after: str) -> None:
    definition = _once(_function(name), before, after, name)
    # Straight to the driver, every percent sign doubled: psycopg reads `%` as a placeholder.
    op.get_bind().exec_driver_sql(definition.replace("%", "%%"))


def upgrade() -> None:
    for table, column in CHECKED:
        name, definition = _constraint(table, column)
        _recreate(table, name, _once(definition, CONSTRAINT_BEFORE, CONSTRAINT_AFTER, name))
    for name, before, after in PATCHES:
        _replace(name, before, after)


def _microsoft_rows() -> bool:
    """Whether any of the five columns holds `microsoft`, seen past every row policy.

    Forced row security binds the table's owner too, so an owner without `BYPASSRLS`, as the
    hosted one is, would find nothing. Each table stops forcing it for this one look, with row
    security off for the transaction, and forces it again before anything else happens.
    """
    conn = op.get_bind()
    tables = [table for table, _ in CHECKED]
    forced = [
        str(name)
        for name in conn.execute(
            text(
                "SELECT r.relname FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace "
                "WHERE n.nspname = 'execbound' AND r.relname = ANY(:names) "
                "AND r.relforcerowsecurity"
            ),
            {"names": tables},
        ).scalars()
    ]
    for table in forced:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    present = conn.execute(
        text(
            "SELECT "
            + " OR ".join(
                # Constants of this file; never input.
                f"EXISTS (SELECT 1 FROM execbound.{table} WHERE {column} = 'microsoft')"  # nosec B608
                for table, column in CHECKED
            )
        )
    ).scalar_one()
    op.execute("SET LOCAL row_security = on")
    for table in forced:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    return bool(present)


def downgrade() -> None:
    if _microsoft_rows():
        raise RuntimeError("MICROSOFT_ROWS_PRESENT")
    for name, _, _ in PATCHES:
        _replace(name, FUNCTION_ADDED, "")
    for table, column in CHECKED:
        name, definition = _constraint(table, column)
        _recreate(table, name, _once(definition, CONSTRAINT_ADDED, "", name))
