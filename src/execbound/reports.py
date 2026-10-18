# SPDX-License-Identifier: AGPL-3.0-only
"""Hold a restore or replay report to named expectations. See docs/RECOVERY.md.

Every check is a flag with one fixed meaning, printed as `PASS <check>` or
`FAIL <check>: expected <x>, found <y>`, then the number of checks and of failures. A failed
check exits 1.
Anything that would let a typo pass exits 2 instead and prints nothing on stdout: an unknown
flag, a tenant name no `--tenant NAME=HEAD_FILE` binds, a status or problem the verifier cannot
report (`execbound.recovery` exports the sets), or a report that is unreadable, larger than
1 MiB, carries a duplicate key, is not version 1 or does not have the shape its writer gives
it. Reports carry no secret, and the checks print only what they compared, never a report.

    restore --report PATH [--tenant NAME=HEAD_FILE]... CHECKS
    replay --report PATH CHECKS
    tenant-id --file HEAD_FILE
"""

import argparse
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, NoReturn
from uuid import UUID

from pydantic import ValidationError

from execbound import recovery
from execbound.replay.models import TrustedHead
from execbound.replay.report import ReplayReport
from execbound.replay.runner import read_bounded
from execbound.requests import _reject_number, _unique_object

MAX_REPORT_BYTES = recovery.MAX_REPORT_BYTES
MAX_HEAD_BYTES = recovery.MAX_CHECKPOINT_BYTES
NAME = re.compile(r"[a-z][a-z0-9_-]{0,15}")
COUNT = re.compile(r"[0-9]{1,9}")
ISSUE = re.compile(r"[A-Z][A-Z0-9_]{0,79}")

# The restore report's shape is the verifier's own: its two row types, and the five fields
# `recovery.verify_restore` returns.
REPORT_FIELDS = frozenset({"version", "ok", "tenants", "provider_stores", "problems"})
TENANT_FIELDS = frozenset(field.name for field in fields(recovery.TenantCheck))
STORE_FIELDS = frozenset(field.name for field in fields(recovery.StoreCheck))
TENANT_COUNTS = ("events", "head_sequence", "unresolved_executions")


class UsageError(ValueError):
    """A check that cannot be evaluated as written: exit 2, never a pass."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise UsageError(message)


class _Once(argparse.Action):
    """A flag that takes one value and may be given once, so a second never silently wins."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            raise UsageError(f"{option_string} is given more than once")
        setattr(namespace, self.dest, values)


@dataclass(frozen=True)
class Result:
    check: str
    expected: str
    found: str
    passed: bool

    def line(self) -> str:
        if self.passed:
            return f"PASS {self.check}"
        return f"FAIL {self.check}: expected {self.expected}, found {self.found}"


# Reading.


def _read(path: Path, limit: int, what: str) -> tuple[bytes, Any]:
    """A file's bytes and its JSON, read strictly: a regular file of at most `limit` bytes,
    no duplicate key, no fraction and no NaN."""
    try:
        raw = read_bounded(Path(path), limit)
    except (OSError, ValueError):
        raise UsageError(f"{what} is unreadable, empty or larger than {limit} bytes") from None
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise UsageError(
            f"{what} is not strict JSON: a duplicate key, a fraction or a syntax error"
        ) from None
    return raw, document


def _version_one(document: Any, what: str) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise UsageError(f"{what} is not a JSON object")
    version = document.get("version")
    if type(version) is not int or version != 1:
        raise UsageError(f"{what} is not version 1")
    return document


def read_head(path: Path, what: str) -> TrustedHead:
    """A checkpoint head file: at most 4 KiB, `tenant_id`, `sequence` and `event_hash`."""
    raw, _ = _read(path, MAX_HEAD_BYTES, what)
    try:
        return TrustedHead.model_validate_json(raw)
    except ValidationError:
        raise UsageError(
            f"{what} is not a head file of tenant_id, sequence and event_hash"
        ) from None


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _count(value: Any) -> bool:
    return type(value) is int and value >= 0


def _canonical_uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def _tenant_row_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and set(row) == TENANT_FIELDS
        and _canonical_uuid(row["tenant_id"])
        and all(_count(row[name]) for name in TENANT_COUNTS)
        and isinstance(row["head_hash"], str)
        and type(row["chain_ok"]) is bool
        and row["checkpoint"] in recovery.CHECKPOINT_STATUSES
        and row["live"] in recovery.LIVE_STATUSES
        and row["fence"] in recovery.FENCE_STATUSES
        and _strings(row["problems"])
    )


def _store_row_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and set(row) == STORE_FIELDS
        and isinstance(row["path"], str)
        and isinstance(row["integrity"], str)
        and (row["journal_records"] is None or _count(row["journal_records"]))
        and _strings(row["problems"])
    )


def read_restore_report(path: Path) -> dict[str, Any]:
    what = "the restore report"
    report = _version_one(_read(path, MAX_REPORT_BYTES, what)[1], what)
    if set(report) != REPORT_FIELDS:
        raise UsageError(f"{what} does not have the verifier's fields")
    if type(report["ok"]) is not bool or not _strings(report["problems"]):
        raise UsageError(f"{what}'s ok or problems are not the verifier's types")
    tenants, stores = report["tenants"], report["provider_stores"]
    if not isinstance(tenants, list) or not isinstance(stores, list):
        raise UsageError(f"{what}'s tenants or provider stores are not lists")
    for index, row in enumerate(tenants, start=1):
        if not _tenant_row_valid(row):
            raise UsageError(f"{what}'s tenant {index} does not have the verifier's fields")
    for index, row in enumerate(stores, start=1):
        if not _store_row_valid(row):
            raise UsageError(f"{what}'s store {index} does not have the verifier's fields")
    if len({row["tenant_id"] for row in tenants}) != len(tenants):
        raise UsageError(f"{what} names one tenant twice")
    return report


def read_replay_report(path: Path) -> ReplayReport:
    what = "the replay report"
    raw, document = _read(path, MAX_REPORT_BYTES, what)
    _version_one(document, what)
    try:
        return ReplayReport.model_validate_json(raw)
    except ValidationError:
        raise UsageError(f"{what} does not have the replay's fields") from None


# Names, statuses and problems.


def bind(bindings: Iterable[str]) -> dict[str, UUID]:
    """`NAME=HEAD_FILE` pairs to tenant ids: each name bound once, each tenant to one name."""
    names: dict[str, UUID] = {}
    for binding in bindings:
        name, separator, path = binding.partition("=")
        if not separator or not path:
            raise UsageError(f"--tenant {binding}: write NAME=HEAD_FILE")
        if not NAME.fullmatch(name):
            raise UsageError(
                f"--tenant {binding}: a name is a lowercase letter and at most 15 more "
                "lowercase letters, digits, hyphens or underscores"
            )
        if name in names:
            raise UsageError(f"{name} is bound twice")
        tenant = read_head(Path(path), f"the head file for {name}").tenant_id
        for other, bound in names.items():
            if bound == tenant:
                raise UsageError(f"{other} and {name} name the same tenant")
        names[name] = tenant
    return names


def _tenant(names: dict[str, UUID], name: str) -> UUID:
    if name not in names:
        raise UsageError(f"{name} is not bound: bind it with --tenant {name}=HEAD_FILE")
    return names[name]


def _items(value: str, flag: str) -> list[str]:
    items = value.split(",")
    if any(not item for item in items):
        raise UsageError(f"{flag} {value}: an item is empty")
    if len(set(items)) != len(items):
        raise UsageError(f"{flag} {value}: an item is named twice")
    return items


def _whole(value: str, flag: str) -> int:
    if not COUNT.fullmatch(value):
        raise UsageError(f"{flag} {value}: not a whole number")
    return int(value)


def _pair(item: str, flag: str) -> tuple[str, str]:
    name, separator, value = item.partition("=")
    if not separator or not name or not value:
        raise UsageError(f"{flag} {item}: write NAME=VALUE")
    return name, value


def _one_of(value: str, valid: frozenset[str], kind: str) -> str:
    if value not in valid:
        raise UsageError(f"{value} is not a {kind}; one of {', '.join(sorted(valid))}")
    return value


def _problem(token: str, names: dict[str, UUID]) -> str:
    """A problem as the report spells it, with a tenant's name expanded to its id."""
    if token in recovery.REPORT_PROBLEMS:
        return token
    kind, _, rest = token.partition(":")
    if kind == "tenant":
        name, separator, code = rest.partition(":")
        if separator and name:
            tenant = _tenant(names, name)
            _one_of(code, recovery.TENANT_PROBLEMS, "tenant problem the verifier reports")
            return f"tenant:{tenant}:{code}"
    if kind == "store":
        path, separator, code = rest.rpartition(":")
        if separator and path:
            _one_of(code, recovery.STORE_PROBLEMS, "store problem the verifier reports")
            return token
    raise UsageError(
        f"{token} is not a problem the verifier reports: write tenant:NAME:CODE, "
        f"store:PATH:CODE or one of {', '.join(sorted(recovery.REPORT_PROBLEMS))}"
    )


def _listing(items: Iterable[str]) -> str:
    return ",".join(sorted(items)) or "none"


def _truth(value: bool) -> str:
    return "true" if value else "false"


# Checks.


def check_restore(args: argparse.Namespace) -> list[Result]:
    names = bind(args.tenant)
    report = read_restore_report(args.report)
    ids = {str(tenant): name for name, tenant in names.items()}
    rows = {row["tenant_id"]: row for row in report["tenants"]}
    problems = set(report["problems"])

    def named(problem: str) -> str:
        kind, _, rest = problem.partition(":")
        tenant, separator, code = rest.partition(":")
        if kind == "tenant" and separator and tenant in ids:
            return f"tenant:{ids[tenant]}:{code}"
        return problem

    found_problems = _listing(named(problem) for problem in problems)
    results: list[Result] = []
    if args.ok is not None:
        label = "ok" if args.ok else "not-ok"
        results.append(
            Result(label, _truth(args.ok), _truth(report["ok"]), report["ok"] is args.ok)
        )
    if args.no_problems:
        results.append(Result("no-problems", "none", found_problems, not problems))
    if args.problems_exactly is not None:
        wanted = {
            _problem(item, names) for item in _items(args.problems_exactly, "--problems-exactly")
        }
        results.append(
            Result(
                f"problems-exactly {args.problems_exactly}",
                _listing(named(problem) for problem in wanted),
                found_problems,
                wanted == problems,
            )
        )
    for token in args.problem:
        present = _problem(token, names) in problems
        results.append(Result(f"problem {token}", "present", found_problems, present))
    for token in args.forbid_problem:
        present = _problem(token, names) in problems
        results.append(
            Result(
                f"forbid-problem {token}", "absent", "present" if present else "absent", not present
            )
        )
    if args.tenants_exactly is not None:
        wanted_names = _items(args.tenants_exactly, "--tenants-exactly")
        wanted_ids = {str(_tenant(names, name)) for name in wanted_names}
        results.append(
            Result(
                f"tenants-exactly {args.tenants_exactly}",
                _listing(wanted_names),
                _listing(ids.get(tenant, tenant) for tenant in rows),
                wanted_ids == set(rows),
            )
        )
    stores = report["provider_stores"]
    if args.stores_ok:
        damaged = [
            f"store:{store['path']}:{problem}" for store in stores for problem in store["problems"]
        ] + [
            f"store:{store['path']}:integrity not ok"
            for store in stores
            if store["integrity"] != "ok" and not store["problems"]
        ]
        found = _listing(damaged) if stores else "no stores"
        results.append(
            Result("stores-ok", "every store intact", found, bool(stores) and not damaged)
        )
    if args.stores_exactly is not None:
        count = _whole(args.stores_exactly, "--stores-exactly")
        results.append(
            Result(f"stores-exactly {count}", str(count), str(len(stores)), len(stores) == count)
        )

    def row(name: str) -> dict[str, Any] | None:
        return rows.get(str(_tenant(names, name)))

    def absent(name: str) -> str:
        return f"no tenant {name} in the report"

    for item in args.checkpoint:
        name, status = _pair(item, "--checkpoint")
        tenant = row(name)
        _one_of(status, recovery.CHECKPOINT_STATUSES, "checkpoint status")
        found = tenant["checkpoint"] if tenant else absent(name)
        results.append(Result(f"checkpoint {item}", status, found, found == status))
    for item in args.live:
        name, status = _pair(item, "--live")
        tenant = row(name)
        _one_of(status, recovery.LIVE_STATUSES, "live status")
        found = tenant["live"] if tenant else absent(name)
        results.append(Result(f"live {item}", status, found, found == status))
    for item in args.fence:
        name, status = _pair(item, "--fence")
        tenant = row(name)
        _one_of(status, recovery.FENCE_STATUSES, "fence status")
        found = tenant["fence"] if tenant else absent(name)
        results.append(Result(f"fence {item}", status, found, found == status))
    for value in args.chain_ok:
        for name in _items(value, "--chain-ok"):
            tenant = row(name)
            found = _truth(tenant["chain_ok"]) if tenant else absent(name)
            results.append(Result(f"chain-ok {name}", "true", found, found == "true"))
    for item in args.unresolved:
        name, value = _pair(item, "--unresolved")
        tenant, count = row(name), _whole(value, "--unresolved")
        found = str(tenant["unresolved_executions"]) if tenant else absent(name)
        results.append(Result(f"unresolved {item}", str(count), found, found == str(count)))
    for item in args.events_min:
        name, value = _pair(item, "--events-min")
        tenant, count = row(name), _whole(value, "--events-min")
        found = str(tenant["events"]) if tenant else absent(name)
        passed = tenant is not None and tenant["events"] >= count
        results.append(Result(f"events-min {item}", f"at least {count}", found, passed))
    return results


def check_replay(args: argparse.Namespace) -> list[Result]:
    report = read_replay_report(args.report)
    decisions = len(report.decisions)
    results: list[Result] = []
    if args.complete is not None:
        label = "complete" if args.complete else "incomplete"
        results.append(
            Result(
                label,
                _truth(args.complete),
                _truth(report.complete),
                report.complete is args.complete,
            )
        )
    if args.issues_exactly is not None:
        wanted = _items(args.issues_exactly, "--issues-exactly")
        for issue in wanted:
            if not ISSUE.fullmatch(issue):
                raise UsageError(
                    f"{issue} is not an issue code: upper case, digits and underscores"
                )
        results.append(
            Result(
                f"issues-exactly {args.issues_exactly}",
                _listing(wanted),
                _listing(report.issues),
                set(wanted) == set(report.issues),
            )
        )
    if args.decisions is not None:
        count = _whole(args.decisions, "--decisions")
        results.append(Result(f"decisions {count}", str(count), str(decisions), decisions == count))
    if args.min_decisions is not None:
        count = _whole(args.min_decisions, "--min-decisions")
        results.append(
            Result(
                f"min-decisions {count}", f"at least {count}", str(decisions), decisions >= count
            )
        )
    return results


# The command.

RESTORE_CHECKS = (
    "ok",
    "no_problems",
    "problems_exactly",
    "problem",
    "forbid_problem",
    "tenants_exactly",
    "stores_ok",
    "stores_exactly",
    "checkpoint",
    "live",
    "fence",
    "chain_ok",
    "unresolved",
    "events_min",
)
REPLAY_CHECKS = ("complete", "issues_exactly", "decisions", "min_decisions")


# The name a usage line and an error carry: the module as `docs/RECOVERY.md` runs it. A wrapper
# script passes its own.
PROG = "python -m execbound.reports"


def _parser(prog: str = PROG) -> argparse.ArgumentParser:
    parser = _Parser(
        prog=prog,
        description="Hold a restore or replay report to named checks; reads only.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    restore = commands.add_parser(
        "restore", allow_abbrev=False, help="Check a report from scripts/verify_restore.py"
    )
    restore.add_argument("--report", type=Path, required=True, action=_Once)
    restore.add_argument(
        "--tenant",
        action="append",
        default=[],
        metavar="NAME=HEAD_FILE",
        help="Bind a name to the tenant of a checkpoint head file",
    )
    whole = restore.add_mutually_exclusive_group()
    whole.add_argument("--ok", dest="ok", action="store_const", const=True)
    whole.add_argument("--not-ok", dest="ok", action="store_const", const=False)
    restore.add_argument("--no-problems", action="store_const", const=True)
    restore.add_argument("--problems-exactly", action=_Once, metavar="PROBLEM,...")
    restore.add_argument("--problem", action="append", default=[])
    restore.add_argument("--forbid-problem", action="append", default=[], metavar="PROBLEM")
    restore.add_argument("--tenants-exactly", action=_Once, metavar="NAME,...")
    restore.add_argument("--stores-ok", action="store_const", const=True)
    restore.add_argument("--stores-exactly", action=_Once, metavar="N")
    restore.add_argument("--checkpoint", action="append", default=[], metavar="NAME=STATUS")
    restore.add_argument("--live", action="append", default=[], metavar="NAME=STATUS")
    restore.add_argument("--fence", action="append", default=[], metavar="NAME=STATUS")
    restore.add_argument("--chain-ok", action="append", default=[], metavar="NAME,...")
    restore.add_argument("--unresolved", action="append", default=[], metavar="NAME=N")
    restore.add_argument("--events-min", action="append", default=[], metavar="NAME=N")

    replay = commands.add_parser("replay", allow_abbrev=False, help="Check a replay's report.json")
    replay.add_argument("--report", type=Path, required=True, action=_Once)
    finished = replay.add_mutually_exclusive_group()
    finished.add_argument("--complete", dest="complete", action="store_const", const=True)
    finished.add_argument("--incomplete", dest="complete", action="store_const", const=False)
    replay.add_argument("--issues-exactly", action=_Once, metavar="CODE,...")
    replay.add_argument("--decisions", action=_Once, metavar="N")
    replay.add_argument("--min-decisions", action=_Once, metavar="N")

    tenant = commands.add_parser(
        "tenant-id", allow_abbrev=False, help="Print the tenant id of a checkpoint head file"
    )
    tenant.add_argument("--file", type=Path, required=True, action=_Once)
    return parser


def _requested(args: argparse.Namespace, checks: Sequence[str]) -> bool:
    """Whether any check was asked for. Every check's default is None or an empty list, so
    `--not-ok` and `--incomplete`, which store False, count."""
    return any(getattr(args, name) not in (None, []) for name in checks)


def main(argv: list[str] | None = None, prog: str = PROG) -> int:
    try:
        args = _parser(prog).parse_args(argv)
        if args.command == "tenant-id":
            print(read_head(args.file, "the head file").tenant_id)
            return 0
        if args.command == "restore":
            if not _requested(args, RESTORE_CHECKS):
                raise UsageError("no checks requested")
            results = check_restore(args)
        else:
            if not _requested(args, REPLAY_CHECKS):
                raise UsageError("no checks requested")
            results = check_replay(args)
    except UsageError as error:
        print(f"{prog}: {error}", file=sys.stderr)
        return 2
    failed = sum(not result.passed for result in results)
    for result in results:
        print(result.line())
    print(f"{len(results)} check{'' if len(results) == 1 else 's'}, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
