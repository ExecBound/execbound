# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduled audit-chain verification (#154, #159): every workspace's chain, read again.

A chain cannot record its own alteration, so detection is verification. `audit-verify` reads
each workspace's chain on the live database from genesis to the head the database keeps, a page
at a time and in one snapshot, recomputing every hash and checking every sequence and link, and
places each retained checkpoint configured for the workspace on that chain. A chain that does
not verify is logged as `audit.chain_failed`, with its code and the sequence where it first
fails, and the run exits 1, which the jobs service records as `job.failed`.

It only reads, as the runtime role and with no workspace credential: it appends no event and
writes no row. It visits every workspace in the directory, an inactive one too, because a
workspace that stopped acting still has a history to protect.

What it cannot see is the readiness pack's first gap: a writer who replaces a whole history and
its stored head together, which only the database owner can do, leaves a chain that verifies.
A retained checkpoint past the rewrite shows it as `DIVERGES_FROM_CHECKPOINT` or
`BEHIND_CHECKPOINT`; with none, nothing here does.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import text

from execbound.audit import GENESIS, ChainWalk
from execbound.db import Database
from execbound.jobs import BUDGET_SECONDS, every_workspace
from execbound.logging_schema import log_event
from execbound.recovery import MAX_CHECKPOINT_BYTES
from execbound.replay.models import TrustedHead
from execbound.replay.runner import read_bounded

COMMAND = "audit-verify"
# A chain's first page, then each page after the last sequence read: every row of the workspace,
# in sequence order, so nothing outside 1..N is skipped.
FIRST_PAGE = text(
    "SELECT * FROM execbound.audit_events WHERE tenant_id = :t ORDER BY sequence LIMIT :n"
)
NEXT_PAGE = text(
    "SELECT * FROM execbound.audit_events WHERE tenant_id = :t AND sequence > :after "
    "ORDER BY sequence LIMIT :n"
)
# Each page is one statement, well inside the transaction's ten-second statement limit.
PAGE_SIZE = 500
MAX_CHECKPOINT_FILES = 1024
# What `audit-export --checkpoint` writes, by the name the recovery runbook gives it.
CHECKPOINT_SUFFIX = ".head.json"

Checkpoints = Mapping[UUID, tuple[TrustedHead, ...]]


class AuditVerifyError(ValueError):
    """A refusal before any workspace is read. The code names the cause, never a path."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Audit verification refused: {code}")


def checkpoint_files(directory: Path) -> list[Path]:
    """The retained heads in a directory: each entry named `*.head.json`. Nothing else there is
    read, so the directory can hold a note beside them; an entry with that name that is not a
    readable file, a link to nothing among them, is refused when it is loaded rather than
    skipped, because it was meant to be a checkpoint."""
    paths: list[Path] = []
    try:
        for path in directory.iterdir():
            if path.name.endswith(CHECKPOINT_SUFFIX):
                paths.append(path)
                if len(paths) > MAX_CHECKPOINT_FILES:
                    raise AuditVerifyError("TOO_MANY_CHECKPOINTS")
    except OSError:
        raise AuditVerifyError("CHECKPOINTS_UNREADABLE") from None
    return sorted(paths)


def load_checkpoints(paths: Iterable[Path]) -> dict[UUID, tuple[TrustedHead, ...]]:
    """Every retained head, by workspace, in sequence order. A workspace may have several,
    retained at different times, and each must sit on its chain; two that name different
    hashes at one sequence cannot both be its history, and are refused."""
    found: dict[UUID, dict[int, TrustedHead]] = defaultdict(dict)
    for path in paths:
        try:
            head = TrustedHead.model_validate_json(read_bounded(Path(path), MAX_CHECKPOINT_BYTES))
        except Exception:
            raise AuditVerifyError("INVALID_CHECKPOINT") from None
        held = found[head.tenant_id].get(head.sequence)
        if held is not None and held != head:
            raise AuditVerifyError("CONFLICTING_CHECKPOINTS")
        found[head.tenant_id][head.sequence] = head
    return {tenant: tuple(heads[s] for s in sorted(heads)) for tenant, heads in found.items()}


@dataclass(frozen=True)
class ChainCheck:
    """One workspace's outcome: how many events verified, and the first problem, if any, with
    the sequence it was found at."""

    events: int
    problem: str | None = None
    sequence: int | None = None


# What a workspace can fail with: the restore verifier's codes (`recovery.py`), and a workspace
# the directory does not hold.
PROBLEMS = frozenset(
    {"CHAIN_BROKEN", "DIVERGES_FROM_CHECKPOINT", "BEHIND_CHECKPOINT", "UNKNOWN_TENANT"}
)


def check_chain(
    db: Database, tenant: UUID, checkpoints: tuple[TrustedHead, ...] = ()
) -> ChainCheck:
    """One workspace's chain, read in one read-only snapshot as the runtime role, and its
    checkpoints.

    Every row of the workspace is read in sequence order, so a row past the head breaks the
    chain as it breaks `verify_chain`. A chain whose rows verify among themselves but do not end
    at the stored head (a truncated tail, rows past the head, or a substituted head) is
    `CHAIN_BROKEN` too. A workspace the directory does not hold is `UNKNOWN_TENANT`, or
    `BEHIND_CHECKPOINT` where a retained head proves it had events: a whole history removed with
    its workspace is a loss the checkpoint shows.
    """
    walk = ChainWalk(tenant, frozenset(head.sequence for head in checkpoints))
    with db.transaction(tenant, snapshot=True) as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        known = conn.execute(
            text("SELECT 1 FROM execbound.tenants WHERE tenant_id = :t"), {"t": tenant}
        ).first()
        if known is None:
            if any(head.sequence > 0 for head in checkpoints):
                return ChainCheck(0, "BEHIND_CHECKPOINT", 1)
            return ChainCheck(0, "UNKNOWN_TENANT")
        stored = conn.execute(
            text("SELECT sequence, event_hash FROM execbound.audit_heads WHERE tenant_id = :t"),
            {"t": tenant},
        ).one_or_none()
        after: int | None = None
        while walk.broken_at is None:
            page = [
                dict(row)
                for row in conn.execute(
                    FIRST_PAGE if after is None else NEXT_PAGE,
                    {"t": tenant, "after": after, "n": PAGE_SIZE},
                ).mappings()
            ]
            for event in page:
                if not walk.add(event):
                    break
            if len(page) < PAGE_SIZE:
                break
            after = int(page[-1]["sequence"])
    if walk.broken_at is not None:
        return ChainCheck(walk.count, "CHAIN_BROKEN", walk.broken_at)
    head_sequence, head_hash = (0, GENESIS) if stored is None else (int(stored[0]), str(stored[1]))
    if not walk.ends_at(head_sequence, head_hash):
        at = head_sequence if walk.count == head_sequence else min(walk.count, head_sequence) + 1
        return ChainCheck(walk.count, "CHAIN_BROKEN", at)
    behind = [head.sequence for head in checkpoints if head.sequence > walk.count]
    for head in checkpoints:
        if head.sequence <= walk.count and walk.hashes[head.sequence] != head.event_hash:
            return ChainCheck(walk.count, "DIVERGES_FROM_CHECKPOINT", head.sequence)
    if behind:
        return ChainCheck(walk.count, "BEHIND_CHECKPOINT", walk.count + 1)
    return ChainCheck(walk.count)


def verify_all(
    db: Database,
    checkpoints: Checkpoints,
    *,
    tenants: Iterable[UUID] | None = None,
    budget_seconds: float = BUDGET_SECONDS,
) -> dict[str, Any]:
    """Every workspace's chain, or the named ones: the directory walk's report, with how many
    chains verified, how many did not, how many events verified, how many retained heads were
    loaded and how many of those this run did not place. A workspace that did not verify is in
    `tenants` with its problem.

    A retained head for a workspace the directory no longer holds is not left unplaced: once a
    run over every workspace has reached them all, each such workspace is checked by name, and
    a history removed with its workspace fails `BEHIND_CHECKPOINT`.
    """
    totals = {"verified": 0, "broken": 0, "events": 0}
    visited: set[UUID] = set()

    def step(tenant: UUID) -> dict[str, Any]:
        visited.add(tenant)
        check = check_chain(db, tenant, tuple(checkpoints.get(tenant, ())))
        totals["events"] += check.events
        if check.problem is None:
            totals["verified"] += 1
            return {}
        totals["broken"] += 1
        log_event(
            "audit.chain_failed",
            level="ERROR",
            command=COMMAND,
            tenant_id=tenant,
            code=check.problem,
            sequence=check.sequence,
        )
        return {"broken": 1, "problem": check.problem, "sequence": check.sequence}

    report = every_workspace(
        db,
        step,
        command=COMMAND,
        tenants=tenants,
        budget_seconds=budget_seconds,
        active_only=False,
    )
    gone = sorted(set(checkpoints) - visited)
    if tenants is None and gone and not report["not_reached"]:
        extra = every_workspace(db, step, command=COMMAND, tenants=gone, active_only=False)
        for count in ("visited", "failed"):
            report[count] += extra[count]
        report["tenants"].update(extra["tenants"])
    unplaced = sum(len(heads) for tenant, heads in checkpoints.items() if tenant not in visited)
    loaded = sum(len(heads) for heads in checkpoints.values())
    return {**report, **totals, "checkpoints": loaded, "checkpoints_unplaced": unplaced}


def failing(report: Mapping[str, Any]) -> bool:
    """Whether the run failed: a chain did not verify, or a workspace's could not be read."""
    return bool(report["broken"] or report["failed"])
