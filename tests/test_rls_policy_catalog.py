# SPDX-License-Identifier: AGPL-3.0-only
"""Every row-level security policy in the schema, by name, command, roles and body.

`check_runtime` reads the row-level security flags and the grants and never a policy's body,
so a migration that widened `tenant_isolation` to `USING (true)`, dropped its `WITH CHECK` or
put a second permissive policy beside it would leave every table forced and every grant
correct while one tenant read another's rows. The isolation tests the checkpoint, Scout and
Arcade schemas carry each prove the body of their own tables by reading across two tenants;
this holds the body of every table at once.

The catalog has two parts. Every table in `TABLES` and `DORMANT_TABLES` carries exactly one
fence: `tenant_isolation`, or on migration 0054's account tables `account_isolation`, a
permissive policy for every command, to PUBLIC, whose `USING` and `WITH CHECK` are both the
fence. Every other policy is named in `LISTED` with its command, its roles, its body and the
reason it exists. A policy in the database that is in neither part is a failure, so a
migration that adds one extends `LISTED` in the same change.

Bodies are compared as PostgreSQL renders them. The expected SQL, written the way the
migrations write it, is created as a probe policy on the same table inside a savepoint that is
rolled back, and the real policy's `pg_policies` text must equal the probe's exactly. The
comparison is exact without depending on how a server version spaces or casts the text.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from typing import NamedTuple

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.db import DORMANT_TABLES, PRIVILEGELESS_TABLES, TABLES

pytestmark = pytest.mark.integration

# The fences, as the migrations write them.
TENANT = "tenant_id = nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
ACCOUNT = "account_id = nullif((SELECT current_setting('execbound.account_id', true)), '')::uuid"

# Migration 0054's account tables. Each is fenced to the signed-in account; three also answer
# to the workspace, because a membership, an allocation and a login proof belong to both.
ACCOUNT_FENCED = frozenset(
    {
        "user_accounts",
        "user_passwords",
        "user_identities",
        "user_factors",
        "user_passkeys",
        "account_sessions",
        "account_provider_links",
        "user_security_events",
    }
)
ACCOUNT_OR_TENANT_FENCED = frozenset(
    {"workspace_memberships", "community_allocations", "account_login_proofs"}
)
# Tables with no tenant or account column, so no fence to carry: the runtime holds no privilege
# on any of them (`db.PRIVILEGELESS_TABLES`, which `check_runtime` holds), and each one's one
# policy is listed below.
UNFENCED = frozenset({"monitor_directory_claims"})

PUBLIC = ("public",)
# Stands for the role that owns the table. `TO CURRENT_USER` names the role that ran the
# migration, which owns every table it created, and that role's name differs by deployment.
OWNER = ("<the table's owner>",)
PROBE = "rls_catalog_probe"
SCRATCH = "rls_catalog_scratch"


@dataclass(frozen=True)
class Shape:
    """One policy as `pg_policies` describes it, or as the catalog requires it."""

    cmd: str
    roles: tuple[str, ...]
    using: str | None
    check: str | None
    permissive: bool = True


LABELS = {
    "cmd": "command",
    "roles": "roles",
    "using": "USING",
    "check": "WITH CHECK",
    "permissive": "permissive",
}

# Every policy that is not a fence: what it is, and why it may exist. Each reads rows outside
# the caller's fence, so each permits one thing and is pinned to its exact command, roles and
# body. A new exception is added here, with its reason, in the change that creates it.
LISTED: dict[tuple[str, str], tuple[Shape, str]] = {
    ("authentication_failures", "unattributed_counters"): (
        Shape("ALL", PUBLIC, "tenant_id IS NULL", "tenant_id IS NULL"),
        "0010: a failure attributed to no tenant carries no subject either, so any role may "
        "count it; a row that names a tenant stays behind tenant_isolation",
    ),
    ("principals", "sign_in_email"): (
        Shape(
            "SELECT",
            PUBLIC,
            "email IS NOT NULL AND email = "
            "nullif((SELECT current_setting('execbound.sign_in_email', true)), '')",
            None,
        ),
        "0040: sign-in reads the one principal whose address the caller typed, before any "
        "tenant is known, and no other row",
    ),
    ("principal_identities", "sign_in_subject"): (
        Shape(
            "SELECT",
            PUBLIC,
            "revoked_at IS NULL AND provider || ':' || subject = "
            "nullif((SELECT current_setting('execbound.sign_in_subject', true)), '')",
            None,
        ),
        "0040: the provider callback reads the one live identity it holds a verified "
        "assertion for, before any tenant is known",
    ),
    ("identity_providers", "directory_provider"): (
        Shape(
            "SELECT",
            PUBLIC,
            "state <> 'disabled' AND provider_id::text = "
            "nullif((SELECT current_setting('execbound.directory_provider', true)), '')",
            None,
        ),
        "0043: a directory sign-in link names a provider and no tenant, so the tenant comes "
        "from the one enabled provider row the link names",
    ),
    ("identity_links", "directory_subject"): (
        Shape(
            "SELECT",
            PUBLIC,
            "revoked_at IS NULL AND provider_id::text || ':' || subject = "
            "nullif((SELECT current_setting('execbound.directory_subject', true)), '')",
            None,
        ),
        "0043: the directory callback reads the one live link for the subject it verified",
    ),
    ("user_accounts", "account_email_lookup"): (
        Shape(
            "SELECT",
            PUBLIC,
            "email = (SELECT current_setting('execbound.sign_in_email', true))",
            None,
        ),
        "0054: account sign-in reads the one account whose address the caller typed, before "
        "any account is signed in",
    ),
    ("user_identities", "account_subject_lookup"): (
        Shape(
            "SELECT",
            PUBLIC,
            "provider = (SELECT current_setting('execbound.sign_in_provider', true)) AND "
            "subject = (SELECT current_setting('execbound.sign_in_subject', true))",
            None,
        ),
        "0054: the account provider callback reads the one identity it verified",
    ),
    ("workspace_invitation_messages", "owner_drain"): (
        Shape("SELECT", OWNER, "true", None),
        "0059: the invitation drain's cross-tenant read, for the owner of its definer "
        "functions alone; the runtime role never matches it",
    ),
    ("weekly_summary_subscriptions", "owner_drain"): (
        Shape("SELECT", OWNER, "true", None),
        "0078: the weekly summary's list of workspaces with a subscriber, for the owner of its "
        "definer functions alone; identifiers only, and the runtime role never matches it",
    ),
    ("weekly_summary_messages", "owner_drain"): (
        Shape("SELECT", OWNER, "true", None),
        "0078: the weekly summary drain's due list and the deployment's sent count, for the "
        "owner of its definer functions alone; the runtime role never matches it",
    ),
    ("dormancy_warnings", "owner_drain"): (
        Shape("SELECT", OWNER, "true", None),
        "0092: the dormancy warning drain's due list and the relay's sent count, for the owner "
        "of its definer functions alone; identifiers or one count, and the runtime role never "
        "matches it",
    ),
    ("approval_email_subscriptions", "owner_drain"): (
        Shape("SELECT", OWNER, "true", None),
        "0096: the approval email pass's list of workspaces with a live subscriber, for the "
        "owner of its definer functions alone; identifiers only, and the runtime role never "
        "matches it",
    ),
    ("approval_emails", "owner_drain"): (
        Shape("SELECT", OWNER, "true", None),
        "0096: the approval email pass's due list and the relay's sent count, for the owner "
        "of its definer functions alone; identifiers or one count, and the runtime role "
        "never matches it",
    ),
    ("job_tenants", "owner_list"): (
        Shape("SELECT", OWNER, "true", None),
        "0064: the scheduled jobs' workspace directory, read across tenants by the owner of "
        "job_tenants_page alone; the runtime role never matches it",
    ),
    ("monitor_directory_claims", "owner_claims"): (
        Shape("ALL", OWNER, "true", "true"),
        "0088: one digest per active Entra connection's directory, naming no tenant, read and "
        "written by the owner of the consent functions and their trigger alone; the runtime "
        "holds no privilege on the table",
    ),
}


class Violation(NamedTuple):
    table: str
    policy: str
    what: str
    found: object = None
    expected: object = None

    def __str__(self) -> str:
        if self.what in {"missing", "unlisted"}:
            return f"{self.table}.{self.policy}: {self.what}"
        return f"{self.table}.{self.policy}: {self.what} is {self.found!r}, not {self.expected!r}"


def fence(table: str) -> tuple[str, str] | None:
    """The name and body of the one fence policy `table` must carry, or None for a table with
    nothing to fence by."""
    if table in UNFENCED:
        return None
    if table in ACCOUNT_FENCED:
        return "account_isolation", ACCOUNT
    if table in ACCOUNT_OR_TENANT_FENCED:
        return "account_isolation", f"{ACCOUNT} OR {TENANT}"
    return "tenant_isolation", TENANT


def found(conn: Connection) -> dict[tuple[str, str], Shape]:
    """Every policy on a table in the schema, as `pg_policies` renders it."""
    rows = conn.execute(
        text("""
        SELECT tablename, policyname, permissive, roles, cmd, qual, with_check
          FROM pg_policies
         WHERE schemaname = 'execbound'
    """)
    ).mappings()
    return {
        (row["tablename"], row["policyname"]): Shape(
            cmd=row["cmd"],
            roles=tuple(row["roles"]),
            using=row["qual"],
            check=row["with_check"],
            permissive=row["permissive"] == "PERMISSIVE",
        )
        for row in rows
    }


def rendered(
    conn: Connection, table: str, cmd: str, using: str | None, check: str | None
) -> tuple[str | None, str | None]:
    """`using` and `check` as PostgreSQL renders them on `table`, from a rolled-back probe."""
    clauses = "".join(
        f" {keyword} ({body})"
        for keyword, body in (("USING", using), ("WITH CHECK", check))
        if body is not None
    )
    savepoint = conn.begin_nested()
    try:
        conn.execute(text(f"CREATE POLICY {PROBE} ON execbound.{table} FOR {cmd}{clauses}"))
        row = conn.execute(
            text(
                "SELECT qual, with_check FROM pg_policies WHERE schemaname = 'execbound' "
                "AND tablename = :table AND policyname = :probe"
            ),
            {"table": table, "probe": PROBE},
        ).one()
    finally:
        savepoint.rollback()
    return row.qual, row.with_check


def expected(
    conn: Connection, tables: Iterable[str], listed: Mapping[tuple[str, str], tuple[Shape, str]]
) -> dict[tuple[str, str], Shape]:
    """The catalog: one fence on each of `tables`, then each listed exception."""
    tables = sorted(tables)
    owners = dict(
        conn.execute(
            text(
                "SELECT relname, pg_get_userbyid(relowner) FROM pg_class "
                "WHERE relnamespace = 'execbound'::regnamespace AND relname = ANY(:tables)"
            ),
            {"tables": sorted({*tables, *(table for table, _ in listed)})},
        ).all()
    )
    catalog: dict[tuple[str, str], Shape] = {}
    for table in tables:
        fenced = fence(table)
        if fenced is None:
            continue
        name, body = fenced
        using, check = rendered(conn, table, "ALL", body, body)
        catalog[(table, name)] = Shape("ALL", PUBLIC, using, check)
    for (table, name), (shape, _reason) in listed.items():
        assert (table, name) not in catalog, f"{table}.{name} is a fence and cannot be listed"
        using, check = rendered(conn, table, shape.cmd, shape.using, shape.check)
        roles = (owners[table],) if shape.roles == OWNER else shape.roles
        catalog[(table, name)] = Shape(shape.cmd, roles, using, check, shape.permissive)
    return catalog


def violations(
    actual: Mapping[tuple[str, str], Shape], catalog: Mapping[tuple[str, str], Shape]
) -> list[Violation]:
    """Every difference between the policies found and the catalog, in a stable order."""
    problems = [Violation(*key, "missing") for key in sorted(catalog.keys() - actual.keys())]
    problems += [Violation(*key, "unlisted") for key in sorted(actual.keys() - catalog.keys())]
    for key in sorted(actual.keys() & catalog.keys()):
        for field in fields(Shape):
            have, want = getattr(actual[key], field.name), getattr(catalog[key], field.name)
            if have != want:
                problems.append(Violation(*key, LABELS[field.name], have, want))
    return problems


def test_every_policy_in_the_schema_is_one_fence_or_a_listed_exception(admin_engine):
    tables = {*TABLES, *DORMANT_TABLES}
    with admin_engine.connect() as conn:
        transaction = conn.begin()
        try:
            problems = violations(found(conn), expected(conn, tables, LISTED))
        finally:
            transaction.rollback()
    assert not problems, "Policies that differ from the catalog:\n" + "\n".join(
        str(problem) for problem in problems
    )


def test_the_catalog_names_only_real_tables_and_gives_every_exception_a_reason():
    tables = set(TABLES)
    assert set(DORMANT_TABLES) <= tables
    assert ACCOUNT_FENCED <= tables and ACCOUNT_OR_TENANT_FENCED <= tables
    assert not ACCOUNT_FENCED & ACCOUNT_OR_TENANT_FENCED
    # A table without a fence is one the runtime cannot touch, and its policy is listed.
    assert UNFENCED <= tables and UNFENCED == PRIVILEGELESS_TABLES
    assert not UNFENCED & (ACCOUNT_FENCED | ACCOUNT_OR_TENANT_FENCED)
    assert UNFENCED <= {table for table, _ in LISTED}
    for (table, name), (shape, reason) in LISTED.items():
        assert table in tables, table
        # A listed policy may sit beside a fence and never replace one.
        fenced = fence(table)
        assert fenced is None or name != fenced[0], (table, name)
        assert reason.strip(), (table, name)
        assert shape.cmd in {"ALL", "SELECT"}, (table, name)
        # A SELECT policy has no WITH CHECK; PostgreSQL refuses one.
        assert (shape.check is None) == (shape.cmd == "SELECT"), (table, name)


FENCE = f"USING ({TENANT}) WITH CHECK ({TENANT})"
UNWRAPPED = "tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid"
# Each case builds policies on a scratch table and names the violations the matcher must find.
# The first is the control: the exact fence passes, so a rejection below is about its shape.
CASES = {
    "the fence itself": ([f"CREATE POLICY tenant_isolation ON {{t}} {FENCE}"], {}, []),
    "a widened USING": (
        [
            f"CREATE POLICY tenant_isolation ON {{t}} "
            f"USING ({TENANT} OR tenant_id IS NULL) WITH CHECK ({TENANT})"
        ],
        {},
        [("tenant_isolation", "USING")],
    ),
    "a missing WITH CHECK": (
        [f"CREATE POLICY tenant_isolation ON {{t}} USING ({TENANT})"],
        {},
        [("tenant_isolation", "WITH CHECK")],
    ),
    "USING (true)": (
        ["CREATE POLICY tenant_isolation ON {t} USING (true) WITH CHECK (true)"],
        {},
        [("tenant_isolation", "USING"), ("tenant_isolation", "WITH CHECK")],
    ),
    "a fence for SELECT alone": (
        [f"CREATE POLICY tenant_isolation ON {{t}} FOR SELECT USING ({TENANT})"],
        {},
        [("tenant_isolation", "command"), ("tenant_isolation", "WITH CHECK")],
    ),
    "a restrictive fence": (
        [f"CREATE POLICY tenant_isolation ON {{t}} AS RESTRICTIVE {FENCE}"],
        {},
        [("tenant_isolation", "permissive")],
    ),
    # A fence granted to one role applies to no other, so the runtime's role would meet no
    # permissive policy on the table. The fence's roles are compared, not only its body.
    "a fence granted to its owner alone": (
        [f"CREATE POLICY tenant_isolation ON {{t}} TO CURRENT_USER {FENCE}"],
        {},
        [("tenant_isolation", "roles")],
    ),
    # The same predicate without the (SELECT ...) that makes the setting an InitPlan, read
    # once per statement rather than once per row (migrations 0003 and 0024).
    "a fence without its InitPlan wrapper": (
        [f"CREATE POLICY tenant_isolation ON {{t}} USING ({UNWRAPPED}) WITH CHECK ({UNWRAPPED})"],
        {},
        [("tenant_isolation", "USING"), ("tenant_isolation", "WITH CHECK")],
    ),
    "no fence at all": ([], {}, [("tenant_isolation", "missing")]),
    "a second policy beside the fence": (
        [
            f"CREATE POLICY tenant_isolation ON {{t}} {FENCE}",
            "CREATE POLICY lookup ON {t} FOR SELECT USING (true)",
        ],
        {},
        [("lookup", "unlisted")],
    ),
    "a listed owner read granted to PUBLIC": (
        [
            f"CREATE POLICY tenant_isolation ON {{t}} {FENCE}",
            "CREATE POLICY owner_read ON {t} FOR SELECT USING (true)",
        ],
        {(SCRATCH, "owner_read"): (Shape("SELECT", OWNER, "true", None), "the self-check")},
        [("owner_read", "roles")],
    ),
    "a listed owner read granted to its owner": (
        [
            f"CREATE POLICY tenant_isolation ON {{t}} {FENCE}",
            "CREATE POLICY owner_read ON {t} FOR SELECT TO CURRENT_USER USING (true)",
        ],
        {(SCRATCH, "owner_read"): (Shape("SELECT", OWNER, "true", None), "the self-check")},
        [],
    ),
}


@pytest.mark.parametrize(("statements", "listed", "wanted"), CASES.values(), ids=CASES.keys())
def test_the_matcher_rejects_each_broken_policy_shape(admin_engine, statements, listed, wanted):
    """The catalog test's own matcher, run on a scratch table the owner creates and rolls back."""
    with admin_engine.connect() as conn:
        transaction = conn.begin()
        try:
            conn.execute(text(f"CREATE TABLE execbound.{SCRATCH} (tenant_id uuid NOT NULL)"))
            for statement in statements:
                conn.execute(text(statement.format(t=f"execbound.{SCRATCH}")))
            actual = {key: shape for key, shape in found(conn).items() if key[0] == SCRATCH}
            problems = violations(actual, expected(conn, [SCRATCH], listed))
        finally:
            transaction.rollback()
    assert [(problem.policy, problem.what) for problem in problems] == wanted
    with admin_engine.connect() as conn:
        assert conn.execute(text(f"SELECT to_regclass('execbound.{SCRATCH}')")).scalar() is None
