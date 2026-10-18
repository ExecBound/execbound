# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a restored gateway database and its companion stores against the audit contract.

The verifier proves that a restore preserved every tenant's audit chain up to its
head, that independently retained checkpoints sit on that chain, that retained
uncertainty survived, and that provider stores are intact. Asked to, it also reads the
restored database as the runtime role and shows every tenant's fence still holds there. It
only reads: it never appends an event, settles an operation, prints a connection string or
contacts a provider. A restore that is older than the live database is reported as a gap,
not hidden; divergence from a checkpoint, a broken chain or a fence that crosses fails the
check.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import TextClause, create_engine, text
from sqlalchemy.engine import URL, Connection, Engine
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from execbound.audit import GENESIS, read_events, verify_chain
from execbound.connection import connect_args, database_url, with_database_name
from execbound.db import UnsafeDatabaseRole, check_runtime
from execbound.plugins import PluginError, load_command_plugins
from execbound.replay.models import TrustedHead
from execbound.replay.runner import read_bounded

MAX_CHECKPOINT_BYTES = 4096
MAX_REPORT_BYTES = 1024 * 1024

# Every status and problem the report can carry. `execbound.reports` reads them from here, so
# a check that names one the verifier cannot produce is refused as a typo rather than failing
# for a reason nobody can read, and an outcome added here is accepted there without an edit.
CHECKPOINT_STATUSES = frozenset(
    {
        "NO_CHECKPOINT",
        "MATCHES_CHECKPOINT",
        "AHEAD_OF_CHECKPOINT",
        "BEHIND_CHECKPOINT",
        "DIVERGES_FROM_CHECKPOINT",
    }
)
LIVE_STATUSES = frozenset(
    {"NOT_COMPARED", "MATCHES_LIVE", "AHEAD_OF_LIVE", "BEHIND_LIVE", "DIVERGES_FROM_LIVE"}
)
# What the runtime role reads of each tenant on the restored database (#155), every tenant the
# copy holds, named or not. Under each tenant's fence every other tenant's row in the copy is
# counted, but that there were any to keep out is shown only by the other tenants, each read
# under its own fence: `HOLDS` when another of them holds rows, `ALONE` when none does, as in
# a copy of one workspace, so a pass that cannot show anything was kept out never reads as
# one that can. The rows are summed over every table, and a policy is seen only through the
# rows it admits: a table holding no row of a tenant but the one whose fence is read tests
# nothing for it, whatever its policy says.
FENCE_STATUSES = frozenset({"NOT_CHECKED", "HOLDS", "ALONE", "CROSSES", "HIDES_OWN"})
FAILING_CHECKPOINT_STATUSES = frozenset({"BEHIND_CHECKPOINT", "DIVERGES_FROM_CHECKPOINT"})
FAILING_LIVE_STATUSES = frozenset({"DIVERGES_FROM_LIVE"})
FAILING_FENCE_STATUSES = frozenset({"CROSSES", "HIDES_OWN"})
TENANT_PROBLEMS = (
    frozenset({"CHAIN_BROKEN"})
    | FAILING_CHECKPOINT_STATUSES
    | FAILING_LIVE_STATUSES
    | FAILING_FENCE_STATUSES
)
STORE_PROBLEMS = frozenset({"STORE_UNREADABLE", "STORE_CORRUPT", "STORE_WITHOUT_JOURNAL"})
REPORT_PROBLEMS = frozenset({"NO_TENANTS_SELECTED", "RUNTIME_UNSAFE"})


class RecoveryError(ValueError):
    """Safe code only; database diagnostics and connection strings never escape."""

    def __init__(self, code: str = "RECOVERY_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Recovery verification unavailable")


@dataclass
class TenantCheck:
    tenant_id: str
    events: int
    head_sequence: int
    head_hash: str
    chain_ok: bool
    unresolved_executions: int
    checkpoint: str
    live: str
    fence: str = "NOT_CHECKED"
    problems: list[str] = field(default_factory=list)


@dataclass
class StoreCheck:
    path: str
    integrity: str
    journal_records: int | None
    problems: list[str] = field(default_factory=list)


def engine_for(url: str | URL, code: str = "INVALID_RESTORED_URL") -> Engine:
    """An engine for a URL the connection rules accept, or the refusal `code`.

    The rules' own messages never escape, and neither does the URL, which can carry a
    password: `--restored-url` is refused as `INVALID_RESTORED_URL`, the default, and the live
    database's URL as `INVALID_DATABASE`, the code its other refusal already reads.
    """
    try:
        parsed = database_url(url)
    except ValueError:
        raise RecoveryError(code) from None
    return create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))


def with_database(url: str | URL, database: str) -> URL:
    """The same connection with another database name, for a restore on one instance.

    The shared helper returns an object, so no password string is created on this path;
    `engine_for` takes the object unchanged.
    """
    try:
        return with_database_name(url, database)
    except ValueError:
        raise RecoveryError("INVALID_DATABASE") from None


# The SQLSTATE PostgreSQL raises when a privilege is missing, on the table, a column, the
# schema or a function a policy calls, and when row security is off and a policy would apply.
_INSUFFICIENT_PRIVILEGE = "42501"


def _unfence(conn: Connection) -> None:
    """Turn row security off for the rest of the transaction. PostgreSQL then refuses a read
    a policy would filter rather than filtering it, so a role that does not bypass row
    security is stopped instead of being given a fenced read (#155)."""
    conn.execute(text("SELECT set_config('row_security', 'off', true)"))


def _refused(exc: DBAPIError) -> bool:
    return getattr(exc.orig, "sqlstate", None) == _INSUFFICIENT_PRIVILEGE


@contextmanager
def _tenant_read(engine: Engine, tenant: UUID, *, unfenced: bool = False) -> Iterator[Connection]:
    """A read-only snapshot under the tenant's fence or, `unfenced`, with row security off: a
    read the role's privileges or a policy refuse is then `OWNER_FENCED`."""
    try:
        with engine.connect() as connection:
            conn = connection.execution_options(isolation_level="REPEATABLE READ")
            with conn.begin():
                conn.execute(text("SET TRANSACTION READ ONLY"))
                conn.execute(text("SELECT set_config('statement_timeout', '30000', true)"))
                conn.execute(
                    text("SELECT set_config('execbound.tenant_id', :tenant, true)"),
                    {"tenant": str(tenant)},
                )
                if unfenced:
                    _unfence(conn)
                yield conn
    except RecoveryError:
        raise
    except DBAPIError as exc:
        if unfenced and _refused(exc):
            raise RecoveryError("OWNER_FENCED") from None
        raise RecoveryError("DATABASE_UNAVAILABLE") from None
    except (SQLAlchemyError, ValueError):
        raise RecoveryError("DATABASE_UNAVAILABLE") from None


def _head(conn: Connection, tenant: UUID) -> tuple[int, str]:
    row = (
        conn.execute(
            text(
                "SELECT sequence, event_hash FROM execbound.audit_heads WHERE tenant_id = :tenant"
            ),
            {"tenant": tenant},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return 0, GENESIS
    return int(row["sequence"]), str(row["event_hash"])


def _unresolved(conn: Connection, tenant: UUID) -> int:
    return int(
        conn.execute(
            text(
                "SELECT count(*) FROM execbound.executions "
                "WHERE tenant_id = :tenant AND state IN ('DISPATCH_COMMITTED', 'INDETERMINATE')"
            ),
            {"tenant": tenant},
        ).scalar_one()
    )


# The tenants with a chain, and every tenant the copy holds: each workspace as well as each
# chain's head, so that a workspace with no history yet is listed too.
_CHAIN_TENANTS = text("SELECT tenant_id FROM execbound.audit_heads ORDER BY tenant_id")
_EVERY_TENANT = text(
    "SELECT tenant_id FROM execbound.tenants UNION "
    "SELECT tenant_id FROM execbound.audit_heads ORDER BY tenant_id"
)


def _list_tenants(engine: Engine, query: TextClause, *, unfenced: bool) -> list[UUID]:
    try:
        with engine.connect() as conn, conn.begin():
            conn.execute(text("SELECT set_config('statement_timeout', '30000', true)"))
            if unfenced:
                _unfence(conn)
            rows = conn.execute(query).all()
        return [UUID(str(row[0])) for row in rows]
    except DBAPIError as exc:
        if unfenced and _refused(exc):
            raise RecoveryError("OWNER_FENCED") from None
        raise RecoveryError("DATABASE_UNAVAILABLE") from None
    except SQLAlchemyError:
        raise RecoveryError("DATABASE_UNAVAILABLE") from None


def enumerate_tenants(engine: Engine, *, unfenced: bool = False) -> list[UUID]:
    """Tenants with a chain visible without a tenant context; empty unless the role bypasses
    RLS, and `OWNER_FENCED` instead when `unfenced` and it does not."""
    return _list_tenants(engine, _CHAIN_TENANTS, unfenced=unfenced)


def every_tenant(engine: Engine) -> list[UUID]:
    """Every tenant the copy holds, its workspaces and its chains' heads, read with row
    security off, so `OWNER_FENCED` for an owner a policy applies to (#155)."""
    return _list_tenants(engine, _EVERY_TENANT, unfenced=True)


def load_checkpoints(paths: Iterable[Path]) -> dict[UUID, TrustedHead]:
    checkpoints: dict[UUID, TrustedHead] = {}
    for path in paths:
        try:
            head = TrustedHead.model_validate_json(read_bounded(Path(path), MAX_CHECKPOINT_BYTES))
        except Exception:
            raise RecoveryError("INVALID_CHECKPOINT") from None
        if head.tenant_id in checkpoints and checkpoints[head.tenant_id] != head:
            raise RecoveryError("CONFLICTING_CHECKPOINTS")
        checkpoints[head.tenant_id] = head
    return checkpoints


def _position(events: list[dict[str, Any]], sequence: int, expected_hash: str) -> bool:
    """Whether the chain carries ``expected_hash`` at ``sequence`` (0 is genesis)."""
    if sequence == 0:
        return expected_hash == GENESIS
    if sequence > len(events):
        return False
    return str(events[sequence - 1]["event_hash"]) == expected_hash


def _checkpoint_status(events: list[dict[str, Any]], head: TrustedHead | None) -> str:
    if head is None:
        return "NO_CHECKPOINT"
    if head.sequence > len(events):
        return "BEHIND_CHECKPOINT"
    if not _position(events, head.sequence, head.event_hash):
        return "DIVERGES_FROM_CHECKPOINT"
    return "MATCHES_CHECKPOINT" if head.sequence == len(events) else "AHEAD_OF_CHECKPOINT"


def _live_status(events: list[dict[str, Any]], live: tuple[int, str] | None) -> str:
    if live is None:
        return "NOT_COMPARED"
    sequence, event_hash = live
    if sequence > len(events):
        return "BEHIND_LIVE"
    if not _position(events, sequence, event_hash):
        return "DIVERGES_FROM_LIVE"
    return "MATCHES_LIVE" if sequence == len(events) else "AHEAD_OF_LIVE"


def _chain_digest(head_sequence: int, head_hash: str, events: list[dict[str, Any]]) -> str:
    """One value for a tenant's head and every event hash on its chain, in order: two reads
    of the chain agree exactly when their digests do."""
    hashes = "\n".join(str(event["event_hash"]) for event in events)
    return hashlib.sha256(f"{head_sequence}:{head_hash}\n{hashes}".encode()).hexdigest()


def _check_tenant(
    engine: Engine,
    tenant: UUID,
    checkpoint: TrustedHead | None,
    live_engine: Engine | None,
    *,
    unfenced: bool = False,
) -> tuple[TenantCheck, str]:
    """The tenant's check, and the digest of the chain the owner read for it: with row
    security off when `unfenced`, so that no policy can filter it."""
    with _tenant_read(engine, tenant, unfenced=unfenced) as conn:
        head_sequence, head_hash = _head(conn, tenant)
        events = read_events(conn, tenant)
        chain_ok = verify_chain(events, tenant, head_sequence, head_hash)
        unresolved = _unresolved(conn, tenant)
    digest = _chain_digest(head_sequence, head_hash, events)
    live: tuple[int, str] | None = None
    if live_engine is not None:
        with _tenant_read(live_engine, tenant) as conn:
            live = _head(conn, tenant)
    check = TenantCheck(
        tenant_id=str(tenant),
        events=len(events),
        head_sequence=head_sequence,
        head_hash=head_hash,
        chain_ok=chain_ok,
        unresolved_executions=unresolved,
        checkpoint=_checkpoint_status(events, checkpoint),
        live=_live_status(events, live),
    )
    if not chain_ok:
        check.problems.append("CHAIN_BROKEN")
    if check.checkpoint in FAILING_CHECKPOINT_STATUSES:
        check.problems.append(check.checkpoint)
    if check.live in FAILING_LIVE_STATUSES:
        check.problems.append(check.live)
    return check, digest


def check_tenant(
    engine: Engine,
    tenant: UUID,
    checkpoint: TrustedHead | None,
    live_engine: Engine | None,
) -> TenantCheck:
    return _check_tenant(engine, tenant, checkpoint, live_engine)[0]


# The fence on the restored database, read as the runtime role (#155).

# Every table with a tenant column whose tenant the runtime role may read, which takes the
# schema's USAGE as well as the column's SELECT. A table it cannot read cannot show it another
# tenant's rows, so only these are counted.
_FENCED_TABLES = text("""
    SELECT c.relname FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
    WHERE n.nspname = 'execbound' AND c.relkind IN ('r', 'p')
      AND has_schema_privilege(current_user, n.oid, 'USAGE')
      AND has_column_privilege(current_user, c.oid, a.attnum, 'SELECT')
    ORDER BY c.relname
""")


# One table's rows of the fenced tenant and of every other, as the runtime role reads them;
# `table` is a quoted identifier read from the catalog.
_COUNT_ROWS = (
    "SELECT count(*) FILTER (WHERE tenant_id = CAST(:t AS uuid)) AS own, "  # nosec B608 - a template; its table is a quoted catalog name
    "count(*) FILTER (WHERE tenant_id <> CAST(:t AS uuid)) AS foreign_rows "
    "FROM execbound.{table}"
)


@dataclass(frozen=True)
class FenceRead:
    """What the runtime role read under one tenant's fence: rows of its own and of any other
    tenant across every table it may read, and the digest of the chain it read, or None when
    the copy's privileges refused reading the chain."""

    own_rows: int
    foreign_rows: int
    chain: str | None


def fence_status(read: FenceRead | None, chain: str, others: int) -> str:
    """One tenant's fence: the runtime's read under it, the digest of the chain the owner read
    for it, and the rows of every other tenant read here that the runtime read under theirs.

    A fence that shows another tenant's row crosses; one that does not show the tenant its
    own chain as the owner reads it hides its own, which would also keep every other tenant
    out and so must not pass; and one that showed no other tenant's row when no other tenant
    read here holds one, so that nothing shows there was a row to keep out, is alone rather
    than holding.
    """
    if read is None:
        return "NOT_CHECKED"
    if read.foreign_rows:
        return "CROSSES"
    if read.chain != chain:
        return "HIDES_OWN"
    return "HOLDS" if others else "ALONE"


def _runtime_safe(engine: Engine) -> tuple[bool, list[str]]:
    """Whether `check_runtime` accepts the role on the restored database, and the tables with
    a tenant column it may read there."""
    try:
        with engine.connect() as connection, connection.begin():
            connection.execute(text("SET TRANSACTION READ ONLY"))
            # The 30-second limit of every other read here: a startup read blocked on the
            # copy, by another session's lock, stops the check below instead of waiting.
            connection.execute(text("SELECT set_config('statement_timeout', '30000', true)"))
            try:
                with connection.begin_nested():
                    check_runtime(connection)
                safe = True
            except UnsafeDatabaseRole:
                safe = False
            except DBAPIError as exc:
                # A read of the copy that its privileges refuse the role, as one without the
                # schema's USAGE is refused the schema revision, is a role the gateway would
                # not start with either; any other failure stops the check below.
                if not _refused(exc):
                    raise
                safe = False
            tables = [str(row[0]) for row in connection.execute(_FENCED_TABLES)]
        return safe, tables
    except SQLAlchemyError:
        raise RecoveryError("RUNTIME_UNAVAILABLE") from None


def _fence_read(engine: Engine, tenant: UUID, tables: list[str]) -> FenceRead:
    """Count, under the tenant's fence, its rows and every other tenant's in `tables`, then
    read its chain. Read only, in one snapshot."""
    try:
        with engine.connect() as connection:
            conn = connection.execution_options(isolation_level="REPEATABLE READ")
            with conn.begin():
                conn.execute(text("SET TRANSACTION READ ONLY"))
                conn.execute(text("SELECT set_config('statement_timeout', '30000', true)"))
                conn.execute(
                    text("SELECT set_config('execbound.tenant_id', :tenant, true)"),
                    {"tenant": str(tenant)},
                )
                own = foreign = 0
                if tables:
                    quote = conn.dialect.identifier_preparer.quote
                    # Names read from the restored catalog, each quoted as an identifier; the
                    # tenant is a bound parameter.
                    counted = " UNION ALL ".join(
                        _COUNT_ROWS.format(table=quote(table)) for table in tables
                    )
                    own, foreign = conn.execute(
                        text(
                            "SELECT coalesce(sum(own), 0), coalesce(sum(foreign_rows), 0) "
                            f"FROM ({counted}) AS counts"  # nosec B608 - quoted catalog names
                        ),
                        {"t": str(tenant)},
                    ).one()
                try:
                    with conn.begin_nested():
                        head_sequence, head_hash = _head(conn, tenant)
                        chain: str | None = _chain_digest(
                            head_sequence, head_hash, read_events(conn, tenant)
                        )
                except DBAPIError as exc:
                    # Only the copy's privileges refusing the read are the fence hiding the
                    # tenant's own history; a timeout, a cancellation or any other failure is
                    # the read failing, and stops the check as `RUNTIME_UNAVAILABLE` below.
                    if not _refused(exc):
                        raise
                    chain = None
        return FenceRead(own_rows=int(own), foreign_rows=int(foreign), chain=chain)
    except SQLAlchemyError:
        raise RecoveryError("RUNTIME_UNAVAILABLE") from None


def _copy(url: URL) -> tuple[str, int, str | None]:
    """Where a connection to `url` goes and the database it reads: the address the connection
    rules pin a loopback name to, or the host, then the port and the database name."""
    args = connect_args(url)
    return str(args.get("hostaddr") or url.host).lower(), int(args["port"]), url.database


def check_fence(runtime: Engine, checks: list[TenantCheck], chains: Mapping[str, str]) -> bool:
    """Read every checked tenant as the runtime role and record each one's fence on its check;
    return whether `check_runtime` accepted the role."""
    safe, tables = _runtime_safe(runtime)
    reads = {
        check.tenant_id: _fence_read(runtime, UUID(check.tenant_id), tables) for check in checks
    }
    for check in checks:
        others = sum(read.own_rows for tenant, read in reads.items() if tenant != check.tenant_id)
        check.fence = fence_status(reads[check.tenant_id], chains[check.tenant_id], others)
        if check.fence in FAILING_FENCE_STATUSES:
            check.problems.append(check.fence)
    return safe


def check_provider_store(path: Path) -> StoreCheck:
    """Integrity of one SQLite provider store, opened read-only."""
    check = StoreCheck(path=str(path), integrity="unreadable", journal_records=None)
    try:
        uri = f"file:{Path(path).resolve().as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()
            check.integrity = str(result[0]) if result else "unknown"
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            if "journal" in tables:
                check.journal_records = int(
                    conn.execute("SELECT count(*) FROM journal").fetchone()[0]
                )
    except sqlite3.Error:
        check.problems.append("STORE_UNREADABLE")
        return check
    if check.integrity != "ok":
        check.problems.append("STORE_CORRUPT")
    if check.journal_records is None:
        check.problems.append("STORE_WITHOUT_JOURNAL")
    return check


def verify_restore(
    *,
    restored_url: str | URL,
    tenants: Iterable[UUID] = (),
    checkpoint_paths: Iterable[Path] = (),
    live_url: str | URL | None = None,
    provider_stores: Iterable[Path] = (),
    runtime_url: str | URL | None = None,
) -> dict[str, Any]:
    """Check a restored database (and stores) and return a report without secrets.

    With `runtime_url`, the runtime role on the restored database, the fence of every tenant
    the copy holds is read as well, the tenants named or not, and a role `check_runtime`
    refuses is a problem of the whole report. That
    URL must reach the same instance and database as `restored_url` (`NO_RUNTIME_DATABASE`),
    and the owner's reads are then made with row security off (`OWNER_FENCED` for an owner a
    policy applies to).
    """
    checkpoints = load_checkpoints(checkpoint_paths)
    engine = engine_for(restored_url)
    engines = [engine]
    try:
        live_engine = engine_for(live_url, "INVALID_DATABASE") if live_url else None
        if live_engine is not None:
            engines.append(live_engine)
        runtime = engine_for(runtime_url, "INVALID_DATABASE") if runtime_url else None
        if runtime is not None:
            engines.append(runtime)
            if _copy(runtime.url) != _copy(engine.url):
                raise RecoveryError("NO_RUNTIME_DATABASE")
    except RecoveryError:
        for each in engines:
            each.dispose()
        raise
    # The fence check holds the runtime role's reads to the owner's, so the owner's are made
    # with row security off: one a policy would filter is refused, never compared.
    unfenced = runtime is not None
    report_problems: list[str] = []
    try:
        selected = list(dict.fromkeys([*tenants, *checkpoints]))
        if unfenced:
            # After a restore every tenant's fence is checked (#155), not only the tenants
            # named: a workspace nobody retained a checkpoint for can be the one a policy lets
            # read the others, which shows only under its own fence. The named tenants come
            # first.
            selected = list(dict.fromkeys([*selected, *every_tenant(engine)]))
        elif not selected:
            selected = enumerate_tenants(engine)
        checked = [
            _check_tenant(engine, tenant, checkpoints.get(tenant), live_engine, unfenced=unfenced)
            for tenant in selected
        ]
        tenant_checks = [check for check, _ in checked]
        if runtime is not None and tenant_checks:
            chains = {check.tenant_id: digest for check, digest in checked}
            if not check_fence(runtime, tenant_checks, chains):
                report_problems.append("RUNTIME_UNSAFE")
    finally:
        for each in engines:
            each.dispose()
    store_checks = [check_provider_store(Path(path)) for path in provider_stores]
    problems = sorted(
        {
            f"tenant:{check.tenant_id}:{problem}"
            for check in tenant_checks
            for problem in check.problems
        }
        | {f"store:{check.path}:{problem}" for check in store_checks for problem in check.problems}
        | set(report_problems)
    )
    if not tenant_checks:
        problems.append("NO_TENANTS_SELECTED")
    return {
        "version": 1,
        "ok": not problems,
        "tenants": [asdict(check) for check in tenant_checks],
        "provider_stores": [asdict(check) for check in store_checks],
        "problems": problems,
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
        raise RecoveryError("REPORT_TOO_LARGE")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a restored ExecBound database and provider stores; reads only."
    )
    parser.add_argument(
        "--restored-database",
        help="Database name to substitute into MIGRATION_DATABASE_URL (same instance)",
    )
    parser.add_argument("--restored-url", help="Owner URL of the restored database")
    parser.add_argument(
        "--compare-live", action="store_true", help="Compare heads with MIGRATION_DATABASE_URL"
    )
    parser.add_argument("--tenant", type=UUID, action="append", default=[])
    parser.add_argument("--checkpoint", type=Path, action="append", default=[])
    parser.add_argument("--provider-store", type=Path, action="append", default=[])
    parser.add_argument(
        "--check-fence",
        action="store_true",
        help="Also read every tenant of the copy as the runtime role: DATABASE_URL with the "
        "--restored-database name substituted",
    )
    parser.add_argument("--output", type=Path, required=True, help="New report file")
    args = parser.parse_args(argv)
    if args.check_fence:
        try:
            # The plugins EXECBOUND_PLUGINS names, before anything reaches the database, so
            # `check_runtime` expects the dormant grants they claim, as `execbound` does.
            load_command_plugins()
        except PluginError as exc:
            print(f"Plugin refused: {exc.code}.", file=sys.stderr)
            return 2
    try:
        live_url = os.environ.get("MIGRATION_DATABASE_URL")
        if args.restored_url:
            restored_url = args.restored_url
        elif args.restored_database and live_url:
            restored_url = with_database(live_url, args.restored_database)
        else:
            raise RecoveryError("NO_RESTORED_DATABASE")
        runtime_url: URL | None = None
        if args.check_fence:
            # The runtime role on the same instance only: a restore named by URL may be on
            # another one, and no runtime URL is guessed for it. `verify_restore` refuses a
            # `DATABASE_URL` that names another instance than `MIGRATION_DATABASE_URL`.
            runtime = os.environ.get("DATABASE_URL")
            if args.restored_url or not runtime:
                raise RecoveryError("NO_RUNTIME_DATABASE")
            runtime_url = with_database(runtime, args.restored_database)
        report = verify_restore(
            restored_url=restored_url,
            tenants=args.tenant,
            checkpoint_paths=args.checkpoint,
            live_url=live_url if args.compare_live else None,
            provider_stores=args.provider_store,
            runtime_url=runtime_url,
        )
        _write_report(args.output, report)
    except RecoveryError as exc:
        print(f"Recovery verification stopped: {exc.code}.", file=sys.stderr)
        return 2
    except OSError:
        print("Recovery verification stopped: report file unavailable.", file=sys.stderr)
        return 2
    summary = ", ".join(
        f"{check['tenant_id'][:8]} events={check['events']} "
        f"chain={'ok' if check['chain_ok'] else 'BROKEN'} checkpoint={check['checkpoint']} "
        f"live={check['live']} fence={check['fence']} "
        f"unresolved={check['unresolved_executions']}"
        for check in report["tenants"]
    )
    print(
        f"Restore verification {'passed' if report['ok'] else 'FAILED'}: {summary or 'no tenants'}"
    )
    for problem in report["problems"]:
        print(f"  problem: {problem}")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
