# SPDX-License-Identifier: AGPL-3.0-only
"""The correlation row: which Arcade execution opened which ExecBound one.

See docs/ARCADE.md, The pre hook and "Duplicate delivery and the idempotency key". The row
is inserted **before** the kernel is called and completed after it, so a crash between the
kernel's commit and the correlation write leaves a row naming the Arcade execution and the
derived key and holding no secret. That shape is not an accident of failure handling: it is
what the pre hook's rule is keyed on. A governed pre hook answers `OK` on a
`DISPATCH_COMMITTED` answer only while **this Arcade execution id's own row holds the
grant's report secret**, so an abandoned decision, a crashed write and a second Arcade id
adopted onto someone else's grant are all refused by one condition with no special case for
any of them.

**Every statement here is scoped `(tenant_id, principal_id, arcade_execution_id)`**, which
is `execution_keys`' own scope with Arcade's id in the place of the derived key, and the
table is keyed the same way. One Arcade project is one ExecBound principal and the Arcade
execution id is the platform's own string, so two projects of one tenant can choose the same
one with no misbehaviour from either. Scoped on the tenant alone, the second project's pre
hook inserted nothing, completed the **first** project's row with its own execution and its
own secret, read `held` back off it and was answered `OK`; both grants then stranded
`UNRESOLVED`, each holding a claim and a cap slot, because neither project's post hook could
reach the execution its own pre hook opened. A write here that matches no row raises rather
than passing silently: a row that was never opened and a scope this module got wrong are
the ways it can match none, and both are the shape that defect had.

The row is correlation and not authority. Nothing here selects a mapping, an action, a
target or an incident, and the decision is `routes._decided`'s: this module hands it one fact
about the row and writes back the code it answers. What the columns carry beyond that fact
is retained so an operator can read Arcade's own log beside ExecBound's — the Arcade
execution id, the derived key, the tool the platform named and the strings it reported.

The report secret is the one credential this extension holds at rest, which is the trust
boundary docs/ARCADE.md states under "The report secret at rest". Three things bound it
here: the completion never reads the stored value back — it asks the database whether one is
there and is answered a boolean — the column is written through
`COALESCE(:secret, report_secret)`, which **prefers the incoming secret** and keeps the
retained one only where the answer carries none, so what it buys is the `regranted` retry of
a duplicate delivery and not immutability; and the post path nulls it at settlement and
clears it opportunistically from the row it reads when a post hook arrives, where that row's
report window has already closed. What keeps a delivery from replacing a secret that settles
someone else's grant is the key, not the `COALESCE`: within one project's own row, every
secret the column can be handed settles the one execution that row names. The residual is
limitation 8: a row no post hook arrives for again keeps its bytes until an operator or a
retention job removes them.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection, CursorResult

from execbound.arcade.models import HookResult, PostHookRequest, PreHookRequest
from execbound.audit import append_event
from execbound.db import Database, check_runtime
from execbound.execution import store as executions
from execbound.execution.models import ExecutionView
from execbound.execution.store import now
from execbound.identity import Identity
from execbound.requests import ActionRequest
from execbound.resolution.models import Clock

# The hook's own facts, written once. `ON CONFLICT DO NOTHING` is what makes a redelivery
# of one Arcade execution id open nothing second: the primary key is
# `(tenant_id, principal_id, arcade_execution_id)`, so within one Arcade project the first
# delivery's row is the row every later one completes, and a second project sending the same
# id opens a row of its own instead of colliding with this one's. A redelivery whose retained
# strings differ from the first delivery's keeps the first delivery's, because these columns
# are outside the runtime's `UPDATE` grant; one whose *intent* differs is refused by the
# kernel instead, on the idempotency key it shares.
_OPEN = text("""
    INSERT INTO execbound.arcade_hooks
      (tenant_id, arcade_execution_id, principal_id, idempotency_key, toolkit, tool_name,
       tool_version, reported_metadata, reported_user_id, created_at)
    VALUES (:tenant, :arcade, :principal, :key, :toolkit, :name, :version,
            CAST(:metadata AS jsonb), :user_id, :now)
    ON CONFLICT (tenant_id, principal_id, arcade_execution_id) DO NOTHING
""")
# The kernel's answer, and the one fact the decision rests on. `execution_id` is written on
# every answer that names an execution; the operation id and the secret are a grant's, so
# `COALESCE` leaves each standing when this answer carries neither. That is what admits the
# `regranted` retry of a duplicate delivery: its answer mints no secret, and the row keeps
# the one the first delivery of this same Arcade id wrote.
_COMPLETE = text("""
    UPDATE execbound.arcade_hooks
    SET execution_id = :execution,
        operation_id = COALESCE(:operation, operation_id),
        report_secret = COALESCE(:secret, report_secret)
    WHERE tenant_id = :tenant AND principal_id = :principal AND arcade_execution_id = :arcade
    RETURNING report_secret IS NOT NULL
""")
# What the extension answered. Retained for the operator reading a refusal beside the grant
# it was refused against, and read by the post path, which treats a denial as a
# contradiction. A redelivery overwrites it, so the column says what the last delivery of
# this Arcade id was answered rather than what the first was.
_DECIDED = text("""
    UPDATE execbound.arcade_hooks SET decision = :decision
    WHERE tenant_id = :tenant AND principal_id = :principal AND arcade_execution_id = :arcade
""")
# The row a post hook's Arcade execution id names, under the key the whole table carries.
# Correlation is the only route from a post hook to an execution, and one Arcade project is
# one ExecBound principal, so a hook arriving on another principal's credential names no row
# here rather than reading or writing that principal's. The kernel would refuse a report for
# another principal's execution anyway — `_reportable` answers NOT_FOUND — and this keeps
# the refusal from touching the row on the way.
_CORRELATED = text("""
    SELECT execution_id, operation_id, report_secret, decision,
           denial_contradiction_at, inputs_contradiction_at, settled_at
    FROM execbound.arcade_hooks
    WHERE tenant_id = :tenant AND principal_id = :principal AND arcade_execution_id = :arcade
""")
# What the platform stated, retained inert for an operator and for the pages. The row keeps
# the **first statement**, written whole: a later delivery is refused by the kernel wherever
# it says something else, and a row that then read differently from the settlement beside it
# would mislead exactly the person reading the two together. A delivery that states no
# result leaves `reported_success` null, so it is not a statement and the statement that
# follows replaces whatever it left.
#
# Each string is cut to its column's width rather than refused: a refusal here settles
# nothing, is never retried and leaves the grant to the sweep, and vendor error text has no
# declared length. Truncating an inert display string decides nothing.
_REPORTED = text("""
    UPDATE execbound.arcade_hooks
    SET reported_success = :success, reported_code = :code, reported_error = :error
    WHERE tenant_id = :tenant AND principal_id = :principal AND arcade_execution_id = :arcade
      AND reported_success IS NULL
""")
# The opportunistic clearing docs/ARCADE.md describes under "The report secret at rest",
# and the settlement's own. `_CLEARED` runs against a row the extension is reading anyway
# whose report window has closed, so nothing can present that secret to the kernel again;
# `_SETTLED` runs when a report settled the execution. Limitation 8 is what neither reaches:
# the bytes of a row nobody reads again.
_CLEARED = text("""
    UPDATE execbound.arcade_hooks SET report_secret = NULL
    WHERE tenant_id = :tenant AND principal_id = :principal AND arcade_execution_id = :arcade
""")
_SETTLED = text("""
    UPDATE execbound.arcade_hooks SET report_secret = NULL, settled_at = COALESCE(settled_at, :now)
    WHERE tenant_id = :tenant AND principal_id = :principal AND arcade_execution_id = :arcade
""")
# One contradiction column, marked under the fence `contradiction` already holds. The column
# name is chosen from `_CONTRADICTIONS` and never from anything a caller sent.
_MARKED = "UPDATE execbound.arcade_hooks SET {column} = :now WHERE tenant_id = :tenant AND principal_id = :principal AND arcade_execution_id = :arcade"  # noqa: E501
# The two contradictions a post hook appends to the tenant's chain, and the column each
# bounds itself with. `DENIED_CALL` is a tool that ran after the extension refused it —
# evidence of a fail-open configuration or a bypass, never a proven one. `INPUTS_DIFFER` is
# a report whose own inputs do not derive the selection the decision froze.
_CONTRADICTIONS = {
    "DENIED_CALL": "denial_contradiction_at",
    "INPUTS_DIFFER": "inputs_contradiction_at",
}
CONTRADICTION_KIND = "execution.control_point_contradiction"
# The widths `0033_reported_failure` gives the two retained platform strings. A value past
# one of them is cut here rather than refused, for the reason `PostHookRequest` states.
REPORTED_CODE_WIDTH = 256
REPORTED_ERROR_WIDTH = 2048


class CorrelationMissing(RuntimeError):
    """A correlation write that matched no row of this project; carries no caller input."""


@dataclass(frozen=True)
class Correlated:
    """What one Arcade execution id names in this tenant, read under one transaction.

    It is correlation and never authority: the decision that produced it was the kernel's,
    and what this carries forward is the execution it opened, the secret that settles it
    and the two facts the post path compares against — the answer the pre hook was given
    and the request the decision froze.

    `report_secret` is the value as it stands **after** the opportunistic clearing, so a
    row whose report window has closed reports none here as well as holding none at rest.
    """

    execution_id: UUID | None
    operation_id: UUID | None
    plan_hash: str | None
    report_secret: str | None
    decision: str | None
    frozen_request: ActionRequest | None
    recorded: frozenset[str]


def _row(identity: Identity, arcade_execution_id: str) -> dict[str, object]:
    """The one key every statement in this module is scoped on, built in one place."""
    return {
        "tenant": identity.tenant_id,
        "principal": identity.principal_id,
        "arcade": arcade_execution_id,
    }


def _moved(result: CursorResult[Any]) -> None:
    """Refuse a write that matched no row, rather than letting it pass as a success.

    Each caller has already established that the row exists: the pre path opened it in a
    committed transaction of its own, and the post path reached here through a read under
    this same key. So the ways this can match nothing are a row that was never opened and a
    scope this module got wrong. Both are what the unkeyed correlation row did: the
    completion and the decision write of a second Arcade project matched the first
    project's row rather than none, and nothing said so. A raise reaches the deployment
    boundary as the application's own 503, which carries no hook code. On the post hook
    that 5xx passes through, and it is what makes Arcade redeliver a settlement; on the pre
    hook the boundary (`arcade/boundary.py`) rewrites it to `CHECK_FAILED`.
    """
    if result.rowcount != 1:
        raise CorrelationMissing("No correlation row for this hook")


def _inert(value: str | None, width: int) -> str | None:
    """A platform string as this table retains it: bounded, and empty is nothing said."""
    if value is None:
        return None
    cut = value[:width]
    return cut or None


def open_hook(db: Database, identity: Identity, hook: PreHookRequest, clock: Clock) -> None:
    """Open this Arcade execution's row before the kernel is asked anything.

    Committed on its own, because a row that shared the kernel's transaction would vanish
    with a decision that committed — which is the one case the rule exists to refuse.

    `check_runtime` is asked here and not in the writes that follow it: this is the
    extension's first write of the request, and between it and the completion the kernel's
    own fence asks the same question, so a role that changed in between fails there.

    The retained strings are the platform's self-description and its end user, inert on
    arrival and inert at rest: `reported_metadata` is the object `ToolMap._consistent`
    weighs, kept so an operator reading a `BEHAVIOR_MISMATCH` sees what was reported, and
    `reported_user_id` is Arcade's attribution and never an ExecBound identity. The hook's
    `inputs` are not retained here — what the decision was taken on is the frozen plan.
    """
    metadata = None if hook.tool.metadata is None else json.dumps(hook.tool.metadata)
    with db.transaction(identity.tenant_id) as conn:
        check_runtime(conn)
        conn.execute(
            _OPEN,
            {
                **_row(identity, hook.execution_id),
                # Arcade's own id is the key when it already matches the kernel's character
                # class, which `routes` checks before this row is opened, so the two columns
                # carry one string rather than an encoding an operator would have to
                # reverse.
                "key": hook.execution_id,
                "toolkit": hook.tool.toolkit,
                "name": hook.tool.name,
                "version": hook.tool.version,
                "metadata": metadata,
                "user_id": hook.context.user_id,
                "now": now(clock),
            },
        )


def complete(
    db: Database,
    identity: Identity,
    arcade_execution_id: str,
    view: ExecutionView,
    answer: Callable[[bool], HookResult],
) -> HookResult:
    """Complete the row with the kernel's answer, and decide on what the row then holds.

    The update and the decision share one transaction, so the `decision` column says what
    was answered on the secret fact this row actually had rather than on one read before or
    after it. `answer` is given that fact and nothing else; it is `routes._decided` bound to
    the view, which keeps the decision table in one place and keeps this module out of it.

    Two deliveries of one project's Arcade id race here, and the row is what serializes
    them: the second update waits for the first to commit and then re-reads, so whichever
    of the two carried the minted secret, the row holds it once both have run. Which of the
    two is answered `OK` does depend on the order — a delivery that completes before the
    delivery holding the minted secret commits sees no secret and is refused. That refusal
    is the fail-closed direction, and what it leaves standing is the reservation, the claim
    and the secret, so the grant is still settleable by this same Arcade id.

    Both of those statements are about one project's own row and hold because the row is
    keyed on the principal. Unkeyed, the two racing deliveries could be two **different**
    principals', and then the `COALESCE` preferred the incoming secret over the retained
    one: the second principal's completion replaced the first's secret, read `held` true off
    a row that now named its own execution, and left the first project's grant with no
    secret anywhere that could settle it. Its post hook reached the second project's
    execution and the kernel answered `NOT_FOUND`.
    """
    grant = view.checkpoint
    with db.transaction(identity.tenant_id) as conn:
        held = bool(
            conn.execute(
                _COMPLETE,
                {
                    **_row(identity, arcade_execution_id),
                    "execution": view.execution_id,
                    "operation": None if grant is None else grant.operation_id,
                    "secret": None if grant is None else grant.report_secret,
                },
            ).scalar_one()
        )
        result = answer(held)
        _moved(
            conn.execute(_DECIDED, {**_row(identity, arcade_execution_id), "decision": result.code})
        )
    return result


def refused(
    db: Database, identity: Identity, arcade_execution_id: str, result: HookResult
) -> HookResult:
    """Record a kernel refusal that named no execution, and hand the answer back.

    `ExecutionError` carries a code and no execution id, so the row keeps the facts it was
    opened with and gains the code the hook answered. A refusal `Runtime.execute` raises
    rather than answering with a view arrives this way, and the codes that do are more than
    the four this said before: `TENANT_STOPPED` ahead of a known key, `BUSY`,
    `IDEMPOTENCY_CONFLICT` and `EXECUTION_UNAVAILABLE`, and `TOO_MANY_GRANTS`,
    `INVALID_BUNDLE` and `NO_ACTIVE_BUNDLE` among them. The surface rate limiter's
    `RATE_LIMITED` does not: it is raised by `checked_request`, ahead of the map and of any
    row, and the route answers it there.

    The code lands on the row of the project whose hook was refused, which is what makes it
    readable beside that project's grant. Unkeyed, a refusal about one project — its own cap
    of eight, say — overwrote another project's retained `OK` where the two had chosen the
    same Arcade execution id, and the other project's post hook then read a recorded answer
    that was not `OK` and appended a `DENIED_CALL` contradiction into the tenant's
    append-only chain: false evidence that the extension had been bypassed.

    The extension's own deadline reaches neither this nor `complete`: nothing was answered,
    so the row stays open exactly as a crash would have left it, and the next delivery of
    that Arcade id — and any other Arcade id admission adopts onto that execution — is
    refused for the same reason. It also spends no second wait on whatever the first gave up
    on.
    """
    with db.transaction(identity.tenant_id) as conn:
        _moved(
            conn.execute(_DECIDED, {**_row(identity, arcade_execution_id), "decision": result.code})
        )
    return result


def correlate(
    db: Database, identity: Identity, hook: PostHookRequest, clock: Clock
) -> Correlated | None:
    """The row this post hook names, with what it stated retained on it, or nothing.

    Correlation is the only route from a post hook to an execution: the hook's own `tool`
    and `context` select nothing, because a mapping chosen from a field the caller supplies
    would be caller input deciding which execution settles. What this returns is the row
    the pre hook opened under the same Arcade execution id, or `None` for a hook that names
    no row of this tenant and principal — including one that overtook its own pre hook,
    since nothing in the published contract orders the two.

    Nothing here inserts. A post hook carries every column the insert needs, so opening a
    row from this side would work and is deliberately not done: the pre hook's
    `ON CONFLICT DO NOTHING` would then keep the tool identity, metadata and user id the
    **post** hook chose, so a platform could name the tool its own correlation row retains
    before ExecBound ever decided anything. The orphan is recorded in the tenant's chain
    instead, which is where every refused request in the kernel is recorded.

    `check_runtime` is asked here because this is the extension's first write of the post
    request; between it and anything that follows, the kernel's own fence asks it again.
    """
    with db.transaction(identity.tenant_id) as conn:
        check_runtime(conn)
        row = conn.execute(_CORRELATED, _row(identity, hook.execution_id)).mappings().one_or_none()
        if row is None:
            return None
        conn.execute(
            _REPORTED,
            {
                **_row(identity, hook.execution_id),
                "success": hook.success,
                "code": _inert(hook.execution_code, REPORTED_CODE_WIDTH),
                "error": _inert(hook.execution_error, REPORTED_ERROR_WIDTH),
            },
        )
        execution = (
            None
            if row["execution_id"] is None
            else executions.read(conn, identity.tenant_id, row["execution_id"])
        )
        secret = _usable_secret(conn, identity, hook.execution_id, dict(row), execution, clock)
        frozen = None
        if execution is not None and execution["frozen"] is not None:
            frozen = executions.frozen(execution).request
        return Correlated(
            execution_id=row["execution_id"],
            operation_id=row["operation_id"],
            plan_hash=None if execution is None else execution["plan_hash"],
            report_secret=secret,
            decision=row["decision"],
            frozen_request=frozen,
            recorded=frozenset(
                name for name, column in _CONTRADICTIONS.items() if row[column] is not None
            ),
        )


def _usable_secret(
    conn: Connection,
    identity: Identity,
    arcade_execution_id: str,
    row: dict[str, Any],
    execution: dict[str, Any] | None,
    clock: Clock,
) -> str | None:
    """The retained secret, cleared here if the window it could be presented in has closed.

    `_reportable` refuses a report past `report_expires_at`, so a secret this row still
    holds after that instant settles nothing and is only a credential at rest. Clearing it
    on the next read the extension makes of that row is the opportunistic rule
    docs/ARCADE.md states; it is not a sweep, and what it does not reach is limitation 8 — a
    row nobody reads again.

    A row naming no execution keeps what it holds, which for such a row is nothing at all:
    the secret is written by the very statement that writes the execution id.

    `_CLEARED` carries no `report_secret IS NOT NULL` clause: this function has already
    returned on a null secret, and the clause is what would have turned a scope that matched
    no row into a write that matched none for a reason of its own. The row it names is the
    one read a few statements earlier in this same transaction, so it must move exactly one.
    """
    secret: str | None = row["report_secret"]
    if secret is None or execution is None or execution["report_expires_at"] is None:
        return secret
    if now(clock) < execution["report_expires_at"]:
        return secret
    _moved(conn.execute(_CLEARED, _row(identity, arcade_execution_id)))
    return None


def contradiction(
    db: Database,
    identity: Identity,
    arcade_execution_id: str,
    name: str,
    payload: dict[str, Any],
    clock: Clock,
) -> bool:
    """Append one contradiction to the tenant's chain, exactly when it moves the row.

    The bound on volume is **the read above the append, taken under the tenant fence**.
    `executions.fence` serializes every writer of this tenant, so between this read of the
    column and the mark that follows it no other delivery can append: a second delivery
    waits at the fence, re-reads a column that is now set and returns having appended
    nothing. One correlation row therefore carries at most one of each of the two kinds.

    The mark itself is not that guard and no longer pretends to be. It carried an
    `AND {column} IS NULL` clause that could only ever be redundant — the fenced read has
    already established the column is null, and this function is the only writer of those
    two columns in the codebase — and being redundant it also could not hold the bound on
    its own: it stops the second **column write** and not the second **append**, which lands
    before it. What a caller past the route's own filter gets is this read, or nothing.

    Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
    """
    column = _CONTRADICTIONS[name]
    with db.transaction(identity.tenant_id) as conn:
        executions.fence(conn, identity.tenant_id, clock)
        already = (
            conn.execute(_CORRELATED, _row(identity, arcade_execution_id)).mappings().one_or_none()
        )
        if already is None or already[column] is not None:
            return False
        append_event(conn, identity.tenant_id, identity.principal_id, CONTRADICTION_KIND, payload)
        _moved(
            conn.execute(
                text(_MARKED.format(column=column)),
                {**_row(identity, arcade_execution_id), "now": now(clock)},
            )
        )
    return True


def settled(db: Database, identity: Identity, arcade_execution_id: str, clock: Clock) -> None:
    """Null the report secret and stamp the instant this Arcade execution's row settled.

    Called for a report that left the execution settled. A settled row is closed to every
    report but its own restatement, and a restatement moves nothing, so the secret has
    nothing left it could do; the report window closing is the other way it stops being
    usable, and `_usable_secret` is where that one is cleared.

    `COALESCE(settled_at, :now)` keeps the first stamp. The route reaches this twice only
    where two deliveries of one post hook both read the secret before either settled: the
    first nulls the secret, so a delivery that starts afterwards returns from `_post` before
    the kernel call and never arrives here. That the stamp is the first is asserted directly
    on this function rather than through the route, because a fixed clock — which is what
    the deployment under test has — writes the same instant twice and hides the difference.
    """
    with db.transaction(identity.tenant_id) as conn:
        _moved(conn.execute(_SETTLED, {**_row(identity, arcade_execution_id), "now": now(clock)}))
