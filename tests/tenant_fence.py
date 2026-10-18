# SPDX-License-Identifier: AGPL-3.0-only
"""The test owner bypasses row security, so a tenant fence on its connection limits nothing.

`admin_engine` connects as `execbound_owner`, which is a superuser with BYPASSRLS in every
local and CI test database. `set_config('execbound.tenant_id', ...)` is what row security
reads, and the owner is exempt from row security, so a read the owner makes after setting
that fence returns every tenant's rows. A test that fences to one tenant and counts rows
without naming the tenant in its statement can pass while proving nothing about that tenant:
the signal conformance suite's cross-tenant check did exactly that until #561 caught it.

This guard turns the case it can see into a failure. A plain read that test code makes on
an owner connection it fenced in the same transaction, from tables that carry `tenant_id`,
with no predicate comparing `tenant_id` to a value, is read again on a separate cursor of
the same transaction: once as the connection's own role and once as the runtime role,
where row security applies, each inside a savepoint rolled back at once. Where the two
answers differ twice running, the read saw rows the fence was meant to exclude, and the
test fails at teardown naming the line.

What it passes over, so that it never fails a test wrongly and never changes one:
- a statement that calls a function, writes, takes a sequence value or an advisory lock, or
  reads a clock, a random value or the current role, because running it again could do
  something twice or answer differently for a reason other than the fence;
- a `LIMIT`, `OFFSET` or `FETCH`, whose rows depend on the plan as much as on the fence;
- a table with no `tenant_id` column, which row security fences some other way or not at
  all, and a fence the transaction has since cleared or rolled back;
- a read the runtime role cannot run, such as a table it holds no grant on;
- product code, because the guard is about what a test's own reads prove.

It sees only what differs while the test runs: a read is caught when another tenant holds
matching rows at that moment, and a predicate on `tenant_id` anywhere in the statement, even
in one subquery, counts as the test's own fence. The second reads go through the driver's own
cursor, never through SQLAlchemy, so they fire no event and no test that counts statements
sees them.
"""

import re
import traceback
import weakref
from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Connection, Engine

OWNER = "execbound_owner"
RUNTIME = "execbound_app"
_HERE = Path(__file__).resolve()
_TESTS = _HERE.parent
_FENCE = re.compile(r"set_config\(\s*'execbound\.tenant_id'", re.IGNORECASE)
_READ = re.compile(r"^[\s(]*(?:WITH|SELECT)\b", re.IGNORECASE)
_TABLES = re.compile(r"\b(?:FROM|JOIN)\s+execbound\.(\w+)", re.IGNORECASE)
# `tenant_id` compared to a bound value or a literal; a join's `a.tenant_id = b.tenant_id` is
# not one, because it fences nothing.
_PREDICATE = re.compile(
    r"\btenant_id\s*(?:=\s*(?:%\(|'|CAST\s*\(\s*%\(|ANY\s*\()|IN\s*\(\s*(?:%\(|'))",
    re.IGNORECASE,
)
_UNREPEATABLE = re.compile(
    r"\b(?:INSERT|DELETE|MERGE)\b|\bUPDATE\s+(?!OF\b|NOWAIT\b|SKIP\b)"
    r"|\bexecbound\.\w+\s*\("
    r"|\b(?:nextval|setval|pg_advisory\w*|random|gen_random_uuid|uuid_generate\w*"
    r"|clock_timestamp|statement_timestamp|timeofday|current_user|session_user|current_role)\b"
    r"|\b(?:LIMIT|OFFSET)\b|\bFETCH\s+(?:FIRST|NEXT)\b",
    re.IGNORECASE,
)

_fenced: "weakref.WeakSet[Any]" = weakref.WeakSet()
_tenanted: dict[str, bool] = {}
_found: list[str] = []
_installed = False


def install() -> None:
    """Listen on every engine of this process; only the owner's connections are looked at."""
    global _installed
    if _installed:
        return
    event.listen(Engine, "after_cursor_execute", _after)
    event.listen(Engine, "commit", _clear)
    event.listen(Engine, "rollback", _clear)
    _installed = True


def take() -> list[str]:
    """The locations found since the last call, which this call forgets."""
    found = list(dict.fromkeys(_found))
    _found.clear()
    return found


def _driver(conn: Connection) -> Any | None:
    """The driver connection under an owner connection, or None for any other one.

    A connection invalidated mid-transaction raises on `conn.connection`; this answers None
    for it rather than turning the error the test is waiting for into another one.
    """
    if conn.engine.url.username != OWNER:
        return None
    try:
        return conn.connection.dbapi_connection
    except Exception:
        return None


def _clear(conn: Connection) -> None:
    # A fence set with `is_local` true ends with its transaction. One set for the session
    # outlives it on the pooled connection, and is not counted again until test code sets
    # a fence in a later transaction: a read missed, never one wrongly failed.
    driver = _driver(conn)
    if driver is not None:
        _fenced.discard(driver)


def _test_code() -> str | None:
    """Where in the tests the statement was issued, or None when test code did not issue it."""
    for frame in reversed(traceback.extract_stack()[:-2]):
        path = Path(frame.filename).resolve()
        if "sqlalchemy" in path.parts or path == _HERE:
            continue
        if _TESTS not in path.parents:
            return None
        return f"{path.relative_to(_TESTS.parent).as_posix()}:{frame.lineno}"
    return None


def _one(dbapi: Any, statement: str, parameters: Any = None) -> Any:
    cursor = dbapi.cursor()
    try:
        cursor.execute(statement, parameters)
        return cursor.fetchone()[0]
    finally:
        cursor.close()


def _has_tenant(dbapi: Any, table: str) -> bool:
    if table not in _tenanted:
        _tenanted[table] = bool(
            _one(
                dbapi,
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = 'execbound' AND table_name = %s "
                "AND column_name = 'tenant_id')",
                (table,),
            )
        )
    return _tenanted[table]


def _answer(dbapi: Any, statement: str, parameters: Any, role: str | None) -> list[str] | None:
    """The statement's rows as `role` reads them, or None where that role cannot read them."""
    cursor = dbapi.cursor()
    try:
        cursor.execute("SAVEPOINT tenant_fence")
        try:
            if role is not None:
                cursor.execute(f"SET LOCAL ROLE {role}")
            cursor.execute(statement, parameters)
            return sorted(repr(row) for row in cursor.fetchall()) if cursor.description else []
        except Exception:
            return None
        finally:
            cursor.execute("ROLLBACK TO SAVEPOINT tenant_fence")
            cursor.execute("RELEASE SAVEPOINT tenant_fence")
    finally:
        cursor.close()


def _differs(dbapi: Any, statement: str, parameters: Any) -> bool:
    own = _answer(dbapi, statement, parameters, None)
    fenced = _answer(dbapi, statement, parameters, RUNTIME)
    return own is not None and fenced is not None and own != fenced


def _after(conn: Connection, cursor, statement: str, parameters, context, executemany) -> None:
    driver = _driver(conn)
    if driver is None or executemany:
        return
    if _FENCE.search(statement):
        if _test_code() is not None:
            _fenced.add(driver)
        return
    if driver not in _fenced or not _READ.match(statement):
        return
    tables = set(_TABLES.findall(statement))
    if not tables or _PREDICATE.search(statement) or _UNREPEATABLE.search(statement):
        return
    where = _test_code()
    if where is None:
        return
    try:
        if not _one(driver, "SELECT current_setting('execbound.tenant_id', true)"):
            return
        if not all(_has_tenant(driver, table) for table in tables):
            return
        # Two answers taken one after the other read two snapshots, so a concurrent writer
        # can part them for a moment; a difference that holds twice is the fence's.
        if _differs(driver, statement, parameters) and _differs(driver, statement, parameters):
            _found.append(where)
    except Exception:
        # Outside a transaction no savepoint can be taken: nothing is compared, and nothing
        # of the test's own was touched.
        return
