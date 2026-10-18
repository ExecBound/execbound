# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded scheduled recovery of committed but unsettled operations from provider evidence."""

from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal, Protocol
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database, UnsafeDatabaseRole
from execbound.execution import store
from execbound.execution.authority import _stale
from execbound.execution.models import ACT_WINDOW, UNSETTLED, EvidenceVerifier, ExecutionError
from execbound.execution.scheduled import RecoveryActor, ScheduledActor, actor_check, enlist
from execbound.identity import Identity
from execbound.policy.store import PolicyStoreError
from execbound.provider.connector import Connector
from execbound.provider.gateway import reconcile_operation
from execbound.resolution.models import Clock, SystemClock

if TYPE_CHECKING:
    from execbound.notifications import Destination

# What one checkpoint grant was when the sweep looked at it under the fence. Four of the
# five are things a run finds and does not act on, and they are counted apart so that
# `unresolved` keeps the one meaning an operator can alert on: a grant that was due and
# would not move.
GrantOutcome = Literal["SWEPT", "OPEN", "UNCERTAIN", "SETTLED", "UNRESOLVED"]


@dataclass
class RecoveryCounts:
    run_id: UUID = field(default_factory=uuid4)
    examined: int = 0
    executed: int = 0
    not_executed: int = 0
    cancelled: int = 0
    unresolved: int = 0
    skipped_no_connector: int = 0
    # Unreported grants moved into retained uncertainty, and claims an assertion settled
    # released now that the act window has passed. Counted apart from the connector
    # outcomes above because neither settles anything and neither asks a provider.
    swept: int = 0
    released: int = 0
    # Approvals nobody answered before their deadline, ended by this run. Counted apart
    # from every connector outcome above because the sweep asks no provider and settles
    # nothing: it ends an authorization that ran out of time, which is a state an
    # approval already has and which, without this sweep, only a late touch reached.
    expired: int = 0
    # The two things a run finds a checkpoint doing and does not act on. A grant inside
    # its report window is healthy and simply not due; a grant already in retained
    # uncertainty has no exit this run can take — the executor's own late report and an
    # administrator's settlement are its two, and neither is a scheduled one. Both used to
    # land in `unresolved`, which made an operator alerting on `unresolved > 0` alert on
    # every live grant five minutes after it was issued and, for a swept one, forever.
    open_grants: int = 0
    uncertain_grants: int = 0
    # A grant something else settled between this run's selection and its sweep: the
    # administrator exit, or the executor's own report arriving inside its window. It
    # moved, so it is neither swept nor unresolved, and a run that classified it from the
    # selection's snapshot called it unresolved — an alert about a row that is finished.
    settled_grants: int = 0

    def grant(self, outcome: GrantOutcome) -> None:
        """Count one checkpoint grant as the sweep found it under the fence."""
        counter = {
            "SWEPT": "swept",
            "OPEN": "open_grants",
            "UNCERTAIN": "uncertain_grants",
            "SETTLED": "settled_grants",
            "UNRESOLVED": "unresolved",
        }[outcome]
        setattr(self, counter, getattr(self, counter) + 1)


class ConnectionSource(Protocol):
    """Anything that opens the connection serving one account, as `Runtime.connection` does:
    a configured connector, a sample account's derived one, or none, and gives the verifier
    it holds for that account's evidence, as `Runtime.evidence_verifier` does."""

    def connection(
        self, tenant_id: UUID, account_id: UUID
    ) -> AbstractContextManager[Connector | None]: ...

    def evidence_verifier(self, tenant_id: UUID, account_id: UUID) -> EvidenceVerifier | None: ...


# A run takes either a fixed map of configured connectors (the tests' rings, and every run
# before #503) or a source that also derives a sample account's connection, which is what
# lets recovery reach the only accounts a workspace made by signup has.
Connections = Mapping[tuple[UUID, UUID], Connector] | ConnectionSource


def _connection(
    connectors: Connections, tenant: UUID, account: UUID
) -> AbstractContextManager[Connector | None]:
    if isinstance(connectors, Mapping):
        return nullcontext(connectors.get((tenant, account)))
    return connectors.connection(tenant, account)


def _verifier(connectors: Connections, tenant: UUID, account: UUID) -> EvidenceVerifier | None:
    """The source's own verifier for the account; a fixed map of connectors holds none."""
    if isinstance(connectors, Mapping):
        return None
    return connectors.evidence_verifier(tenant, account)


class RecoveryStopped(ExecutionError):
    """The run's actor stopped being current part-way (#503, defect 2).

    Always INVALID_IDENTITY: the administrator is no longer a current ADMIN (a revoked
    credential, for one), or the workspace or its scheduler principal is no longer active.
    Where it is raised differs between the two actors, because their checks fail differently:

    - An administrator's run stops only at the recheck before an operation (`_current`). A
      revocation that lands inside an operation makes that operation's own check fail with
      `PolicyStoreError`, which the operation reports as a dependency that did not answer,
      so it costs that one operation and the recheck before the next one stops the run.
    - A scheduled run also stops inside an operation, because the scheduled check refuses
      with INVALID_IDENTITY itself. An unsettled execution it interrupted is counted
      `unresolved`, as an administrator's would be; an interrupted claim release or
      approval expiry is not counted, because those counts say only what moved.

    A recheck that fails for any other reason never raises this (`_current`). Everything the
    run had already committed stands and is carried in `counts`, so a report can say what a
    stopped run did as well as why it stopped.
    """

    def __init__(self, code: str, counts: RecoveryCounts) -> None:
        super().__init__(code)
        self.counts = counts


def _current(db: Database, admin: RecoveryActor, clock: Clock) -> None:
    """Recheck the actor before an operation (#503, defect 2).

    A revoked administrator or a deactivated workspace used to cost every remaining row one
    refused attempt each, counted as unresolved. Checked here, it stops the run at the next
    operation instead.

    Only a refused actor stops it. A recheck that could not be answered at all, the database
    not answering above all, says nothing about the actor, and stopping the whole run for it
    would turn a transient failure that used to cost one row into one that costs every row
    after it. The operation goes ahead instead, and its own checks, which are the ones that
    guard its writes, decide it exactly as they did before this recheck existed.
    """
    try:
        with db.transaction(admin.tenant_id) as conn:
            actor_check(conn, admin, clock)
    except (ExecutionError, PolicyStoreError) as exc:
        if exc.code == "INVALID_IDENTITY":
            raise ExecutionError("INVALID_IDENTITY") from None
        return
    except SQLAlchemyError:
        return


def select_unsettled(
    db: Database, admin: RecoveryActor, *, grace: timedelta, limit: int, clock: Clock
) -> list[dict[str, Any]]:
    """Unsettled executions older than the grace period, oldest first; no fence is taken here."""
    with db.transaction(admin.tenant_id) as conn:
        actor_check(conn, admin, clock)
        rows = (
            conn.execute(
                text(
                    "SELECT execution_id, state, dispatch_attempted_at, report_expires_at, frozen "
                    "FROM execbound.executions WHERE tenant_id=:t "
                    "AND state IN ('DISPATCH_COMMITTED', 'INDETERMINATE') "
                    "AND changed_at <= :cutoff ORDER BY created_at, execution_id LIMIT :limit"
                ),
                {"t": admin.tenant_id, "cutoff": store.now(clock) - grace, "limit": limit},
            )
            .mappings()
            .all()
        )
        actor_check(conn, admin, clock)
    return [dict(row) for row in rows]


def select_held_claims(
    db: Database, admin: RecoveryActor, *, grace: timedelta, limit: int, clock: Clock
) -> list[UUID]:
    """Settled grants whose claim an assertion left standing and whose act window has passed.

    The canonical claim of an asserted execution is held until the act window has passed,
    because an executor that could free the target by claiming success would take a grant,
    report without acting and re-request the same target at once. Nothing else releases such
    a claim: attested evidence against a settled row is refused by the outcome route and an
    administrator's is refused by ``reconcile``, so this selection is the exit.

    The act window is measured from ``dispatch_attempted_at``, the stamp that marks the
    single attempt as consumed. The deadline the executor was actually given is
    ``min(grant clock + ACT_WINDOW, plan validity, credential expiry)``, and the grant
    clock is read a few statements after that stamp in the same transaction, so this
    boundary can precede the real one by that interval and by nothing else; the grace
    period the run takes on top of it is measured in minutes. The settlement tier is
    paired with a state, as the checkpoint markers are everywhere else: the tier is
    written only by a settlement, and a settled state is what says there is nothing
    further coming for this grant.
    """
    with db.transaction(admin.tenant_id) as conn:
        actor_check(conn, admin, clock)
        rows = conn.execute(
            text(
                "SELECT e.execution_id FROM execbound.executions e "
                "JOIN execbound.resource_claims c "
                "ON c.tenant_id = e.tenant_id AND c.execution_id = e.execution_id "
                "WHERE e.tenant_id=:t AND e.report_expires_at IS NOT NULL "
                "AND e.settlement_tier = 'ASSERTED' "
                "AND NOT (e.state = ANY(CAST(:unsettled AS text[]))) "
                "AND c.released_at IS NULL AND e.dispatch_attempted_at <= :acted "
                "AND e.changed_at <= :cutoff ORDER BY e.created_at, e.execution_id LIMIT :limit"
            ),
            {
                "t": admin.tenant_id,
                "unsettled": list(UNSETTLED),
                "acted": store.now(clock) - ACT_WINDOW,
                "cutoff": store.now(clock) - grace,
                "limit": limit,
            },
        ).scalars()
        held = [UUID(str(value)) for value in rows]
        actor_check(conn, admin, clock)
    return held


def select_lapsed_approvals(
    db: Database, admin: RecoveryActor, *, grace: timedelta, limit: int, clock: Clock
) -> list[UUID]:
    """Executions still held for a person whose approval ran out of time; no fence here.

    An approval reaches EXPIRED only when something touches it, and nothing touches one that
    the agent never retried and no human ever opened, so it stays PENDING for as long as the
    tenant keeps its rows. An APPROVED approval the agent never came back to consume is
    selected on the same terms, because it is the same clock that ran out and the plan it
    was bound to is no longer valid either.

    The grace period is the run's own, measured from the approval's expiry, so a decision
    landing in the same second as the deadline is never racing a sweep. It is why the
    console compares ``expires_at`` to the server's clock rather than trusting the state
    alone: between the expiry and the next run the row is readable and must read as lapsed.
    """
    with db.transaction(admin.tenant_id) as conn:
        actor_check(conn, admin, clock)
        rows = conn.execute(
            text(
                "SELECT e.execution_id FROM execbound.executions e "
                "JOIN execbound.approvals a "
                "ON a.tenant_id = e.tenant_id AND a.execution_id = e.execution_id "
                "WHERE e.tenant_id=:t AND e.state='PENDING_APPROVAL' "
                "AND a.state IN ('PENDING', 'APPROVED') AND a.expires_at <= :cutoff "
                "ORDER BY e.created_at, e.execution_id LIMIT :limit"
            ),
            {"t": admin.tenant_id, "cutoff": store.now(clock) - grace, "limit": limit},
        ).scalars()
        lapsed = [UUID(str(value)) for value in rows]
        actor_check(conn, admin, clock)
    return lapsed


def expire_approval(db: Database, admin: RecoveryActor, execution_id: UUID, clock: Clock) -> bool:
    """End one approval past its deadline, exactly as a late touch would have ended it.

    ``_stale`` is the same helper the agent's late retry and the human's late decision call,
    so the approval reaches EXPIRED and the execution STALE_AUTHORIZATION through one
    writer and the chain holds the same pair of transitions a late touch writes. The actor
    is this run's own, its ADMIN or, for a scheduled pass, the workspace's scheduler
    principal (#503), which is the honest answer to who ended it.

    Nothing is released, because a pending approval holds nothing: admission writes the
    impact row and the canonical claim on the path that reserves, after an approval has
    been verified and consumed, and a row that never got there never charged a scope.

    Every condition is re-read under the fence, so this is idempotent — a second run finds
    the row settled and answers False — and a decision arriving in the same instant either
    takes the fence first, in which case the approval is no longer PENDING here, or takes
    it second, in which case ``decide_approval`` refuses it for the same reason.
    """
    with db.transaction(admin.tenant_id) as conn:
        # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
        store.fence(conn, admin.tenant_id, clock)
        actor_check(conn, admin, clock)
        row = store.read(conn, admin.tenant_id, execution_id)
        if row["state"] != "PENDING_APPROVAL":
            return False
        approval = store.approval_row(conn, row)
        if (
            approval is None
            or approval["state"] not in {"PENDING", "APPROVED"}
            or store.now(clock) < approval["expires_at"]
        ):
            return False
        _stale(conn, row, admin, clock, approval, "APPROVAL_EXPIRED")
        actor_check(conn, admin, clock)
    return True


def _window_open(row: Mapping[str, Any], clock: Clock) -> bool:
    """Whether the report window this grant was given has still to close.

    The sweep's own condition, asked under the fence beside every other one, so what a run
    reports about a grant and what it did to it come from one read of one row.
    """
    return bool(store.now(clock) < row["report_expires_at"])


def sweep_grant(
    db: Database, admin: RecoveryActor, execution_id: UUID, clock: Clock
) -> GrantOutcome:
    """Move one unreported grant past its report window into retained uncertainty.

    Nothing is settled, refunded or released: the impact stays UNRESOLVED and the canonical
    claim stays held, which is what keeps the grant counted against its principal's cap and
    its target unavailable until an administrator settles it from the executor's own record.
    The cancellation this run offers a dispatched operation is refused for a grant, in
    ``dispatch._never_a_checkpoint``, because a non-execution on absent executor evidence is
    the refund the execution contract forbids.

    Every condition is re-read under the fence, so a report that landed between the
    selection and here decides instead of this run — and what this returns is read from
    the same fenced row, so what a run reports about a grant is what was true when it
    looked and never what the selection's snapshot said minutes earlier. Classified from
    the snapshot, a grant an administrator settled or an executor reported in that gap was
    counted UNRESOLVED, which is the one answer that means "due, and would not move".
    """
    actor = admin.principal_id
    if actor is None:
        raise ExecutionError("INVALID_IDENTITY")
    with db.transaction(admin.tenant_id) as conn:
        # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
        store.fence(conn, admin.tenant_id, clock)
        actor_check(conn, admin, clock)
        row = store.read(conn, admin.tenant_id, execution_id)
        if row["report_expires_at"] is None:
            # Not a checkpoint at all. `recover` never asks about one, because it pairs
            # the column with the state before it calls; nothing here may assume that.
            return "UNRESOLVED"
        if row["state"] not in UNSETTLED:
            return "SETTLED"
        if row["state"] == "INDETERMINATE":
            return "UNCERTAIN"
        if _window_open(row, clock):
            return "OPEN"
        store.transition(conn, row, actor, "INDETERMINATE", clock, reason="UNREPORTED_GRANT")
        actor_check(conn, admin, clock)
    return "SWEPT"


def release_claim(db: Database, admin: RecoveryActor, execution_id: UUID, clock: Clock) -> bool:
    """Release the canonical claim a settled assertion left held, and say so in the chain.

    The execution is not touched: it stays settled, at tier ASSERTED, with its impact
    confirmed, because what the act window's closing ends is the executor's authority to
    act on the grant and not the charge for what it says it did. A claim release rides
    along with a settlement everywhere else, so this is the one that needs an event of its
    own; it carries identifiers and the tier and never anything the executor sent.
    """
    actor = admin.principal_id
    if actor is None:
        raise ExecutionError("INVALID_IDENTITY")
    with db.transaction(admin.tenant_id) as conn:
        # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
        store.fence(conn, admin.tenant_id, clock)
        actor_check(conn, admin, clock)
        row = store.read(conn, admin.tenant_id, execution_id)
        if (
            row["report_expires_at"] is None
            or row["settlement_tier"] != "ASSERTED"
            or row["state"] in UNSETTLED
            or row["dispatch_attempted_at"] is None
            or store.now(clock) < row["dispatch_attempted_at"] + ACT_WINDOW
        ):
            return False
        released = conn.execute(
            text(
                "UPDATE execbound.resource_claims SET released_at=:n "
                "WHERE tenant_id=:t AND execution_id=:e AND released_at IS NULL"
            ),
            {"n": store.now(clock), "t": row["tenant_id"], "e": row["execution_id"]},
        ).rowcount
        if not released:
            return False
        append_event(
            conn,
            row["tenant_id"],
            actor,
            "execution.claim_released",
            {
                "execution_id": str(row["execution_id"]),
                "operation_id": str(row["operation_id"]),
                "plan_hash": row["plan_hash"],
                "settlement_tier": row["settlement_tier"],
                "reason": "ACT_WINDOW_CLOSED",
            },
        )
        actor_check(conn, admin, clock)
    return True


def _attempted[Answer](
    step: Callable[[Database, RecoveryActor, UUID, Clock], Answer],
    db: Database,
    admin: RecoveryActor,
    execution_id: UUID,
    clock: Clock,
    *,
    refused: Answer,
) -> Answer:
    """Run one row's step, leaving the row alone if it could not be taken.

    A bounded run does not stop for one row, exactly as it does not stop for a provider
    that will not answer: what it could not move stays unsettled and the next run sees it
    again. A scheduled actor's refusal is the exception: the scheduled check raises
    INVALID_IDENTITY for an inactive workspace, and it is re-raised because every later
    row would be refused for the same reason. An administrator's is not: the ADMIN check
    refuses a revoked credential with `PolicyStoreError`, a `ValueError`, so the row is left
    as one that could not be taken, and the recheck before the next operation (`_current`)
    is what stops that run.

    ``refused`` is what the step's answer is taken to be when it could not be taken at
    all, supplied by the caller because only it knows what that means: a claim was not
    released, and a grant was due and would not move.
    """
    try:
        return step(db, admin, execution_id, clock)
    except ExecutionError as exc:
        if exc.code == "INVALID_IDENTITY":
            raise
        return refused
    except (SQLAlchemyError, ValueError):
        return refused


def recover(
    db: Database,
    admin: RecoveryActor,
    connectors: Connections,
    *,
    limit: int = 50,
    grace: timedelta = timedelta(seconds=300),
    cancel_unattempted: bool = False,
    clock: Clock | None = None,
) -> RecoveryCounts:
    """One bounded run. Every settlement goes through the reconciliation path; nothing is
    sent, and a never-attempted operation is only ever cancelled when explicitly enabled.

    ``limit`` bounds each of the three selections, so a run examines at most that many
    unsettled executions, releases at most that many claims an assertion settled and ends
    at most that many approvals past their deadline. They are separate because a settled
    grant is in neither the unsettled set nor anything a connector can answer for, and an
    approval nobody answered is in none of the three; what a run leaves behind the next
    run sees.

    ``admin`` is an administrator's identity, or a scheduled pass's actor (#503), which holds
    no credential: it may do everything here except ask a provider for a tombstone, and it
    gains its scheduler principal once any of the three selections returns a row, so a
    workspace with nothing due gains none. The actor is rechecked before every operation, and
    a refused actor raises `RecoveryStopped` with what the run had already done."""
    clock = clock or SystemClock()
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ExecutionError("INVALID_LIMIT")
    if not timedelta(seconds=60) <= grace <= timedelta(days=1):
        raise ExecutionError("INVALID_GRACE")
    if cancel_unattempted and not isinstance(admin, Identity):
        # Cancellation is the one provider write recovery can make; it stays behind an
        # administrator (#503).
        raise ExecutionError("INVALID_IDENTITY")
    counts = RecoveryCounts()
    try:
        selected = select_unsettled(db, admin, grace=grace, limit=limit, clock=clock)
        held = select_held_claims(db, admin, grace=grace, limit=limit, clock=clock)
        lapsed = select_lapsed_approvals(db, admin, grace=grace, limit=limit, clock=clock)
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None
    if isinstance(admin, ScheduledActor) and (selected or held or lapsed):
        admin = enlist(db, admin, clock)
    reason = f"Scheduled recovery {counts.run_id}"
    try:
        for row in selected:
            _current(db, admin, clock)
            counts.examined += 1
            if row["report_expires_at"] is not None:
                # A checkpoint before the connector is looked up, because a grant has no
                # connector by construction: ExecBound dispatched nothing and the executor
                # holds the vendor credential. Taken on the row's own marker paired with its
                # state, which is DISPATCH_COMMITTED or INDETERMINATE here, so a denied or
                # stale row that carries an unused window is never one of these.
                #
                # What the grant was is the sweep's to say, because the sweep is what reads
                # it under the fence. A row already uncertain, one still inside its window and
                # one something settled in the meantime are none of them anomalies, so none
                # is counted as one; what is left in `unresolved` is a grant that was due and
                # would not move, which is also what a step that could not be taken leaves.
                try:
                    outcome: GrantOutcome = _attempted(
                        sweep_grant, db, admin, row["execution_id"], clock, refused="UNRESOLVED"
                    )
                except ExecutionError:
                    # The grant the refusal interrupted is due and did not move.
                    counts.unresolved += 1
                    raise
                counts.grant(outcome)
                continue
            frozen = store.frozen(row)
            never_attempted = row["dispatch_attempted_at"] is None
            try:
                # Inside the row's own `try`: a sample account's connection is derived by
                # reading its account, and a failure there costs this row, not the run.
                with _connection(connectors, admin.tenant_id, frozen.intent.account_id) as (
                    connector
                ):
                    if connector is None:
                        counts.skipped_no_connector += 1
                        continue
                    if never_attempted and not cancel_unattempted:
                        # The provider never received a send; there is nothing to look up
                        # and no authority to cancel, so the operation stays as it is.
                        counts.unresolved += 1
                        continue
                    view = reconcile_operation(
                        db,
                        admin,
                        row["execution_id"],
                        connector,
                        reason=reason,
                        cancel_if_missing=cancel_unattempted and never_attempted,
                        clock=clock,
                        verifier=_verifier(connectors, admin.tenant_id, frozen.intent.account_id),
                    )
            except ExecutionError as exc:
                # A refusal costs its one row. An actor refused part-way costs the operation
                # it interrupted in the same way (#503), and then the run stops.
                counts.unresolved += 1
                if exc.code == "INVALID_IDENTITY":
                    raise
                continue
            if view.state == "EXECUTED":
                counts.executed += 1
            elif view.state == "FAILED_NOT_EXECUTED" and never_attempted:
                counts.cancelled += 1
            elif view.state in {"FAILED_NOT_EXECUTED", "STALE_AUTHORIZATION"}:
                counts.not_executed += 1
            else:
                counts.unresolved += 1
        for execution_id in held:
            _current(db, admin, clock)
            if _attempted(release_claim, db, admin, execution_id, clock, refused=False):
                counts.released += 1
        for execution_id in lapsed:
            _current(db, admin, clock)
            # A row this run could not take stays exactly as it is and the next run sees it
            # again, as everywhere else here; only what moved is counted.
            if _attempted(expire_approval, db, admin, execution_id, clock, refused=False):
                counts.expired += 1
    except ExecutionError as exc:
        # Only a refused actor gets here: `_current`'s refusal, or a scheduled actor's refused
        # by an operation's own check. Every other refusal is one row's and was counted
        # inside the loop, and `_current` lets any other failure of its own go by.
        raise RecoveryStopped(exc.code, counts) from None
    return counts


class SweepFailed(ExecutionError):
    """A sweep riding on a workspace's scheduled recovery failed (#503).

    `recover_scheduled` runs two sweeps once `recover` has returned: settling the queued
    notifications, and retiring old assistant text. Each runs whether or not the other
    failed, and everything already committed stands: `recover`'s work and any sweep that
    finished. `counts` carries that report, `recover`'s counts and one key for each sweep that
    finished, so a report can say what the workspace's pass did as well as why it failed. The
    code is the first failed sweep's own.

    Not a `RecoveryStopped`, which always means a refused actor: a sweep can fail for any
    reason, the database not answering above all.
    """

    def __init__(self, code: str, counts: SimpleNamespace) -> None:
        super().__init__(code)
        self.counts = counts


def recover_scheduled(
    db: Database,
    tenant: UUID,
    connections: Connections,
    *,
    destinations: "Sequence[Destination]" = (),
    limit: int = 50,
    grace: timedelta = timedelta(seconds=300),
    clock: Clock | None = None,
) -> dict[str, Any]:
    """One workspace's scheduled recovery (#503): no workspace credential, the scheduler as
    the actor, and the two sweeps that ride on it.

    Retirement used to ride on an administrator's run; the pass reaches every workspace, so it
    rides here now. So does settling queued notifications: rows whose approval is closed, and
    rows whose destination is gone (older than `ORPHAN_AFTER`), which no drain may reach
    again. The first kind overlaps with what a drain would do, harmlessly: nothing is sent,
    and the drain would settle the row the same way. `destinations` is this deployment's
    whole configuration, and a row whose destination it does not name counts as gone, so a
    caller must pass it.

    A sweep that fails raises `SweepFailed` with what the run had already committed.
    """
    from execbound.assistant.turns import AssistantError, retire_due_turns
    from execbound.notifications import settle_orphaned

    clock = clock or SystemClock()
    actor = ScheduledActor(tenant)
    # If `recover` raises, neither sweep runs. For a refused actor, whether `RecoveryStopped`
    # or a selection's own refusal, that loses nothing: the scheduler principal cannot be
    # changed (`principals_system_frozen`), so a scheduled actor is refused only for an
    # inactive workspace, which both sweeps' checks would refuse too.
    counts = recover(db, actor, connections, limit=limit, grace=grace, clock=clock)
    report: dict[str, Any] = dict(vars(counts))
    failed: str | None = None
    sweeps: tuple[tuple[str, Callable[[], int]], ...] = (
        ("notifications_settled", partial(settle_orphaned, db, actor, destinations, clock=clock)),
        ("assistant_turns_retired", partial(retire_due_turns, db, actor, clock)),
    )
    for key, sweep in sweeps:
        try:
            report[key] = sweep()
        except UnsafeDatabaseRole:
            # Never one workspace's failure: the database is not the schema this code expects.
            raise
        except (AssistantError, SQLAlchemyError, ValueError) as exc:
            # `ExecutionError` and `PolicyStoreError` are `ValueError`s that carry a code, as
            # `AssistantError` does. A database failure or any other `ValueError` carries
            # none of ours, and is the dependency that did not answer.
            code = (
                exc.code
                if isinstance(exc, AssistantError | ExecutionError | PolicyStoreError)
                else "EXECUTION_UNAVAILABLE"
            )
            failed = failed or code
    if failed is not None:
        raise SweepFailed(failed, SimpleNamespace(**report))
    return report
