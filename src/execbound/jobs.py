# SPDX-License-Identifier: AGPL-3.0-only
"""Scheduled jobs over many tenants: the directory walk, and the older token map.

The scheduled pass (#503) holds no workspace credential. `every_workspace` walks the directory
of tenants through its owner-only listing function (migration 0064), or the workspaces its
caller names (the drain's destination workspaces), and runs one step per active workspace. One
workspace's refusal is that workspace's outcome and never the run's; a database that is not
exactly the schema this code expects stops the run before it visits anything.

`for_each_tenant` is the older form, kept for an operator's own schedule and for a plugin's
command over a tenants file: it walks a file mapping tenant ids to tokens and runs the step as
each tenant's ADMIN. The file is materialized by ``boot.py`` from ``EXECBOUND_JOBS_TOKENS_JSON``.
"""

import json
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.assistant.turns import AssistantError
from execbound.db import Database, DormantGrantsRefused, UnsafeDatabaseRole, check_runtime
from execbound.execution.models import ExecutionError
from execbound.execution.scheduled import tenant_active
from execbound.getting_started import OnboardingError
from execbound.identity import AuthenticationFailed, Identity, authenticate
from execbound.logging_schema import log_event
from execbound.monitoring.models import MonitorError
from execbound.policy.store import PolicyStoreError
from execbound.replay.runner import read_bounded

MAX_TENANTS = 64
MAX_TOKEN_BYTES = 160
MAX_FILE_BYTES = 64 * 1024
PAGE_SIZE = 200
# Inside the Compose scheduler's 600-second kill (`schedule.JOB_TIMEOUT_SECONDS`), so a run
# stops starting workspaces before it is stopped itself.
BUDGET_SECONDS = 480
# What one workspace's step may fail with: that workspace's outcome, never the run's.
CONTAINED = (
    AssistantError,
    AuthenticationFailed,
    ExecutionError,
    OnboardingError,
    PolicyStoreError,
    SQLAlchemyError,
    ValueError,
)


class TenantsFileError(ValueError):
    """Worded here; the message names the file's shape and never a value."""


def _token(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= MAX_TOKEN_BYTES
        and value.isascii()
        and not any(character.isspace() for character in value)
    )


def read_tenants_file(path: Path) -> dict[UUID, str]:
    """A JSON object of canonical tenant id to token, one to sixty-four entries."""
    try:
        document = json.loads(read_bounded(path, MAX_FILE_BYTES).decode("ascii"))
    except (OSError, ValueError, UnicodeDecodeError):
        raise TenantsFileError("tenants file is unreadable or not JSON") from None
    if type(document) is not dict or not 1 <= len(document) <= MAX_TENANTS:
        raise TenantsFileError(f"tenants file must map 1 to {MAX_TENANTS} tenants")
    tokens: dict[UUID, str] = {}
    for key, value in document.items():
        try:
            tenant = UUID(str(key))
        except ValueError:
            raise TenantsFileError("tenants file has a malformed tenant id") from None
        if str(tenant) != key or not _token(value):
            raise TenantsFileError("tenants file has a malformed entry")
        tokens[tenant] = value
    return tokens


def _refusal(exc: BaseException) -> str:
    if isinstance(exc, AuthenticationFailed):
        return "INVALID_IDENTITY"
    if isinstance(
        exc, AssistantError | ExecutionError | MonitorError | OnboardingError | PolicyStoreError
    ):
        return exc.code
    return "DEPENDENCY_UNAVAILABLE"


def for_each_tenant(
    db: Database,
    tokens: Mapping[UUID, str],
    step: Callable[[Identity], Mapping[str, Any]],
    *,
    command: str,
) -> dict[str, dict[str, Any]]:
    """Run ``step`` as each tenant's ADMIN; a tenant that refuses is recorded and skipped.

    The token must authenticate as an ADMIN of the tenant it is filed under; anything else
    is ``INVALID_IDENTITY`` without saying which. An unclaimed slot's tenant is inactive, so
    its jobs token is refused exactly as an expired one would be.

    A database whose dormant grants are not what this process's plugins claim, most often
    one holding a plugin's grants in a process that has not loaded it, is not a tenant's
    refusal: every tenant would meet it, and no tenant's state fixes it. It stops the run,
    so the command names the fix and exits 2 (#496), rather than every tenant being
    skipped with a code that says nothing about the cause.
    """
    outcomes: dict[str, dict[str, Any]] = {}
    for tenant, token in tokens.items():
        try:
            identity = authenticate(db, token)
            if identity.tenant_id != tenant or identity.kind != "ADMIN":
                raise ExecutionError("INVALID_IDENTITY")
            outcomes[str(tenant)] = dict(step(identity))
        except DormantGrantsRefused:
            raise
        except (
            AssistantError,
            AuthenticationFailed,
            ExecutionError,
            OnboardingError,
            PolicyStoreError,
            SQLAlchemyError,
            UnsafeDatabaseRole,
            ValueError,
        ) as exc:
            code = _refusal(exc)
            outcomes[str(tenant)] = {"skipped": code}
            log_event("job.skipped", level="WARNING", command=command, tenant_id=tenant, code=code)
    return outcomes


def check_directory_policy(conn: Connection) -> None:
    """The directory's policies are exactly the two migration 0064 makes, as it made them.

    `tenant_isolation`, permissive, for every command; and `owner_list`, permissive, for
    `SELECT`, for the listing function's owner alone, reading every row. Nothing else: a
    restrictive policy, a narrowed `owner_list` or a missing one would leave the listing
    function reading nothing, so the pass would visit no workspace and say nothing; a widened
    one would let more than that function read the directory. `check_runtime` covers tables,
    grants and functions but not policies, so this reads `pg_policy` itself, as the invitations
    drain does for its own.
    """
    rows = (
        conn.execute(
            text("""
        SELECT pol.polname, pol.polcmd, pol.polpermissive,
               ARRAY(SELECT pg_get_userbyid(r) FROM unnest(pol.polroles) r) AS roles,
               pg_get_expr(pol.polqual, pol.polrelid) AS qual,
               (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p
                  JOIN pg_namespace n ON n.oid = p.pronamespace
                 WHERE n.nspname = 'execbound' AND p.proname = 'job_tenants_page') AS owner
          FROM pg_policy pol
         WHERE pol.polrelid = 'execbound.job_tenants'::regclass
    """)
        )
        .mappings()
        .all()
    )
    policies = {row["polname"]: row for row in rows}
    if set(policies) != {"tenant_isolation", "owner_list"}:
        raise ExecutionError("UNSAFE_JOB_POLICY")
    isolation, listing = policies["tenant_isolation"], policies["owner_list"]
    if (
        not isolation["polpermissive"]
        or isolation["polcmd"] != "*"
        or not listing["polpermissive"]
        or listing["polcmd"] != "r"
        or list(listing["roles"]) != [listing["owner"]]
        or listing["qual"] != "true"
    ):
        raise ExecutionError("UNSAFE_JOB_POLICY")


def _directory(db: Database, start: UUID) -> Iterator[UUID]:
    """Every tenant in the directory, from just after `start` round to `start` itself."""
    for after, stop in ((start, None), (None, start)):
        cursor: UUID | None = after
        while True:
            # The transaction only holds a connection: the listing function's own policy
            # decides what it lists, so any tenant id opens one.
            with db.transaction(uuid4()) as conn:
                page = [
                    UUID(str(value))
                    for value in conn.execute(
                        text("SELECT tenant_id FROM execbound.job_tenants_page(:a, :n)"),
                        {"a": cursor, "n": PAGE_SIZE},
                    ).scalars()
                ]
            for tenant in page:
                if stop is not None and tenant > stop:
                    return
                yield tenant
            if len(page) < PAGE_SIZE:
                break
            cursor = page[-1]


def every_workspace(
    db: Database,
    step: Callable[[UUID], Mapping[str, Any]],
    *,
    command: str,
    tenants: Iterable[UUID] | None = None,
    budget_seconds: float = BUDGET_SECONDS,
    start: UUID | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    active_only: bool = True,
) -> dict[str, Any]:
    """Run ``step`` once for every active workspace, or every workspace with
    ``active_only=False``, with no workspace credential (#503).

    ``tenants`` names the workspaces; without it the pass walks the directory from just after
    ``start`` (random unless a test names one) round to ``start`` itself, so a run its budget
    cuts short leaves a different tail each time. A workspace reached once the budget is spent
    is counted and not visited, and an inactive one is counted and not logged. A workspace
    whose step refuses, or whose activity could not be read, is visited and failed: that
    workspace's outcome, with what the step had already done when the refusal carries its
    `counts`. A database that is not the schema this code expects stops the run.

    A step that only reads, such as the audit-chain verification, passes ``active_only=False``
    and visits an inactive workspace too: its history still needs protecting, and a pass that
    writes nothing has nothing to stop there.
    """
    with db.transaction(uuid4()) as conn:
        check_runtime(conn)
        if tenants is None:
            check_directory_policy(conn)
    walk = _directory(db, start or uuid4()) if tenants is None else iter(tenants)
    began = monotonic()
    report: dict[str, Any] = {
        "visited": 0,
        "inactive": 0,
        "failed": 0,
        "not_reached": 0,
        "tenants": {},
    }
    for tenant in walk:
        if monotonic() - began >= budget_seconds:
            report["not_reached"] += 1
            continue
        try:
            if active_only and not tenant_active(db, tenant):
                report["inactive"] += 1
                continue
            outcome = dict(step(tenant))
        except UnsafeDatabaseRole:
            raise
        except CONTAINED as exc:
            # Visited whether the step or the activity check refused, so that `failed` is
            # always a part of `visited`.
            report["visited"] += 1
            report["failed"] += 1
            code = _refusal(exc)
            entry: dict[str, Any] = {"skipped": code}
            counts = getattr(exc, "counts", None)
            if counts is not None:
                entry.update(vars(counts))
            report["tenants"][str(tenant)] = entry
            log_event("job.skipped", level="WARNING", command=command, tenant_id=tenant, code=code)
            continue
        report["visited"] += 1
        if any(type(value) is int and value > 0 for value in outcome.values()):
            report["tenants"][str(tenant)] = outcome
    return report
