# SPDX-License-Identifier: AGPL-3.0-only
"""A person's turns: rows written only through the database's definer functions.

A turn is RUNNING while the loop works, then COMPLETED with an answer or FAILED with one
reason from a closed list. The rows are the asking person's own: every read is by the actor
and every write goes through a function that checks the actor owns the turn, so an
administrator cannot read an approver's questions. A turn still RUNNING long after it was
created reads as FAILED (`ABANDONED`) and is persisted so on the first read, which also
covers a process restart mid-turn. Thirty days after completion `retire_turns` nulls the
text and keeps the counts. The tenant switch lives beside the other tenant switches on
`tenant_policy_control` and is set by an ADMIN with a reason, audited, never silently.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound.assistant.client import Usage
from execbound.audit import acted_with, append_event
from execbound.db import Database
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.execution.scheduled import ScheduledActor, scheduled_check
from execbound.identity import Identity
from execbound.policy.store import PolicyStoreError
from execbound.resolution.models import Clock
from execbound.secrets import secret_shaped

CONTEXT_KINDS = ("question", "execution", "approval", "finding", "agent", "policy_change")
FAILURE_REASONS = (
    "TOOL_LIMIT",
    "TIME_LIMIT",
    "TOKEN_LIMIT",
    "REFUSED_SECRET",
    "RECOMMENDATION",
    "MODEL_ERROR",
    "ABANDONED",
)
PERSONS = frozenset({"HUMAN_APPROVER", "ADMIN"})
RETENTION = timedelta(days=30)
LIST_LIMIT = 20
# Every code a definer function or this module can answer with; anything else is unavailable.
CODES = frozenset(
    {
        "INVALID_TENANT",
        "INVALID_ACTOR",
        "INVALID_TURN",
        "INVALID_STATE",
        "INVALID_PROPOSAL",
        "INVALID_BUNDLE",
        "INVALID_CONTEXT",
        "INVALID_QUESTION",
        "INVALID_MODEL",
        "INVALID_STEP",
        "STEP_LIMIT",
        "INVALID_USAGE",
        "INVALID_ANSWER",
        "INVALID_REASON",
        "INVALID_IDENTITY",
        "ASSISTANT_OFF",
        "PERSON_LIMIT",
        "TENANT_LIMIT",
    }
)


class AssistantError(Exception):
    """A refusal by code; the message is the code and nothing from the row or the request."""

    def __init__(self, code: str = "ASSISTANT_UNAVAILABLE") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Turn:
    turn_id: UUID
    principal_id: UUID
    context_kind: str
    context_id: UUID | None
    question: str | None
    state: str
    reason: str | None
    steps: tuple[str, ...]
    answer: dict[str, Any] | None
    cited_ids: tuple[str, ...]
    model: str
    tool_names: tuple[str, ...]
    input_tokens: int
    cached_tokens: int
    output_tokens: int
    created_at: datetime
    completed_at: datetime | None
    retired_at: datetime | None


@dataclass(frozen=True)
class Caps:
    """The operator's caps, checked when a turn is created; a cost control, not a fence."""

    person_hourly_turns: int
    tenant_daily_tokens: int


@dataclass(frozen=True)
class SwitchChange:
    previous: bool
    enabled: bool


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> Any:
    """Run one definer function; a refusal surfaces as its code and nothing else."""
    try:
        return conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        raise AssistantError(message if message in CODES else "ASSISTANT_UNAVAILABLE") from None


def _check(
    conn: Connection, identity: Identity, clock: Clock, kind: str, *, workspace: bool = False
) -> None:
    """The store's identity check, answered in this module's own error type.

    ``workspace`` asks for an administrator who holds the whole workspace rather than some
    spaces (`store.workspace_admin_check`), as the tenant's own switch takes.
    """
    try:
        if workspace:
            store.workspace_admin_check(conn, identity, clock)
        else:
            store.identity_check(conn, identity, clock, kind)
    except (ExecutionError, PolicyStoreError) as exc:
        raise AssistantError(exc.code if exc.code in CODES else "INVALID_IDENTITY") from None


def _person(conn: Connection, identity: Identity, clock: Clock) -> None:
    if identity.kind not in PERSONS:
        raise AssistantError("INVALID_IDENTITY")
    _check(conn, identity, clock, identity.kind)


def _turn(row: Any) -> Turn:
    answer = row["answer"]
    return Turn(
        turn_id=row["turn_id"],
        principal_id=row["principal_id"],
        context_kind=str(row["context_kind"]),
        context_id=row["context_id"],
        question=row["question"],
        state=str(row["state"]),
        reason=row["reason"],
        steps=tuple(str(step) for step in row["steps"]),
        answer=dict(answer) if isinstance(answer, dict) else None,
        cited_ids=tuple(str(value) for value in row["cited_ids"]),
        model=str(row["model"]),
        tool_names=tuple(str(name) for name in row["tool_names"]),
        input_tokens=int(row["input_tokens"]),
        cached_tokens=int(row["cached_tokens"]),
        output_tokens=int(row["output_tokens"]),
        created_at=row["created_at"],
        completed_at=row["completed_at"],
        retired_at=row["retired_at"],
    )


def _own_rows(
    conn: Connection, identity: Identity, *, turn_id: UUID | None, limit: int
) -> list[Turn]:
    # One literal, so the scanner and a reader see the whole statement as written.
    rows = conn.execute(
        text(
            "SELECT turn_id, principal_id, context_kind, context_id, question, state, reason, "
            "steps, answer, cited_ids, model, tool_names, input_tokens, cached_tokens, "
            "output_tokens, created_at, completed_at, retired_at "
            "FROM execbound.assistant_turns "
            "WHERE tenant_id=:t AND principal_id=:p "
            "AND (CAST(:i AS uuid) IS NULL OR turn_id=:i) "
            "ORDER BY created_at DESC, turn_id DESC LIMIT :limit"
        ),
        {"t": identity.tenant_id, "p": identity.principal_id, "i": turn_id, "limit": limit},
    ).mappings()
    return [_turn(row) for row in rows]


def tenant_switch(conn: Connection, tenant: UUID) -> bool:
    row = conn.execute(
        text("SELECT assistant_enabled FROM execbound.tenant_policy_control WHERE tenant_id=:t"),
        {"t": tenant},
    ).scalar_one_or_none()
    return bool(row)


def create_turn(
    db: Database,
    identity: Identity,
    *,
    context_kind: str,
    context_id: UUID | None,
    question: str | None,
    model: str,
    clock: Clock,
    caps: Caps | None = None,
) -> Turn:
    """A new RUNNING turn for this person, refused when the tenant's switch is off or a cap
    is reached. The caps are counted in the same transaction as the insert."""
    turn_id = uuid4()
    with db.transaction(identity.tenant_id) as conn:
        _person(conn, identity, clock)
        now = store.now(clock)
        if not tenant_switch(conn, identity.tenant_id):
            raise AssistantError("ASSISTANT_OFF")
        if caps is not None:
            hourly = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.assistant_turns "
                    "WHERE tenant_id=:t AND principal_id=:p AND created_at > :since"
                ),
                {
                    "t": identity.tenant_id,
                    "p": identity.principal_id,
                    "since": now - timedelta(hours=1),
                },
            ).scalar_one()
            if int(hourly) >= caps.person_hourly_turns:
                raise AssistantError("PERSON_LIMIT")
            daily = conn.execute(
                text(
                    "SELECT coalesce(sum(input_tokens + output_tokens), 0) "
                    "FROM execbound.assistant_turns WHERE tenant_id=:t AND created_at > :since"
                ),
                {"t": identity.tenant_id, "since": now - timedelta(days=1)},
            ).scalar_one()
            if int(daily) >= caps.tenant_daily_tokens:
                raise AssistantError("TENANT_LIMIT")
        _call(
            conn,
            "SELECT execbound.assistant_turn_create(:actor, :turn, :kind, :context, :question, "
            ":model, :now)",
            {
                "actor": identity.principal_id,
                "turn": turn_id,
                "kind": context_kind,
                "context": context_id,
                "question": question,
                "model": model,
                "now": now,
            },
        )
        return _own_rows(conn, identity, turn_id=turn_id, limit=1)[0]


def append_step(db: Database, identity: Identity, turn_id: UUID, step: str, clock: Clock) -> int:
    with db.transaction(identity.tenant_id) as conn:
        _person(conn, identity, clock)
        return int(
            _call(
                conn,
                "SELECT execbound.assistant_turn_step(:actor, :turn, :step)",
                {"actor": identity.principal_id, "turn": turn_id, "step": step},
            )
        )


def complete_turn(
    db: Database,
    identity: Identity,
    turn_id: UUID,
    *,
    state: str,
    clock: Clock,
    reason: str | None = None,
    answer: dict[str, Any] | None = None,
    cited_ids: Sequence[str] = (),
    tool_names: Sequence[str] = (),
    usage: Usage | None = None,
) -> None:
    usage = usage or Usage()
    with db.transaction(identity.tenant_id) as conn:
        _person(conn, identity, clock)
        _call(
            conn,
            "SELECT execbound.assistant_turn_complete(:actor, :turn, :state, :reason, "
            "CAST(:answer AS jsonb), CAST(:cited AS jsonb), CAST(:tools AS jsonb), "
            ":input, :cached, :output, :now)",
            {
                "actor": identity.principal_id,
                "turn": turn_id,
                "state": state,
                "reason": reason,
                "answer": json.dumps(answer) if answer is not None else None,
                "cited": json.dumps(list(cited_ids)),
                "tools": json.dumps(list(tool_names)),
                "input": usage.input_tokens,
                "cached": usage.cache_read_input_tokens,
                "output": usage.output_tokens,
                "now": store.now(clock),
            },
        )


def read_turn(
    db: Database,
    identity: Identity,
    turn_id: UUID,
    clock: Clock,
    *,
    abandon_after_seconds: int = 90,
) -> Turn:
    """The person's own turn, or `INVALID_TURN`; a stale RUNNING turn is persisted as
    abandoned first, so the row says what the page says."""
    with db.transaction(identity.tenant_id) as conn:
        _person(conn, identity, clock)
        found = _own_rows(conn, identity, turn_id=turn_id, limit=1)
        if not found:
            raise AssistantError("INVALID_TURN")
        turn = found[0]
        now = store.now(clock)
        stale = now - turn.created_at >= timedelta(seconds=abandon_after_seconds)
        if turn.state == "RUNNING" and stale:
            _call(
                conn,
                "SELECT execbound.assistant_turn_complete(:actor, :turn, 'FAILED', 'ABANDONED', "
                "NULL, '[]'::jsonb, '[]'::jsonb, 0, 0, 0, :now)",
                {"actor": identity.principal_id, "turn": turn_id, "now": now},
            )
            turn = _own_rows(conn, identity, turn_id=turn_id, limit=1)[0]
        return turn


def list_turns(
    db: Database, identity: Identity, clock: Clock, *, limit: int = LIST_LIMIT
) -> list[Turn]:
    with db.transaction(identity.tenant_id) as conn:
        _person(conn, identity, clock)
        return _own_rows(conn, identity, turn_id=None, limit=max(1, min(limit, LIST_LIMIT)))


def retire_turns(db: Database, admin: Identity, clock: Clock) -> int:
    """Null the text of every turn completed thirty days ago; the counts stay."""
    with db.transaction(admin.tenant_id) as conn:
        _check(conn, admin, clock, "ADMIN")
        return int(
            _call(
                conn,
                "SELECT execbound.assistant_turn_retire(:actor, :now)",
                {"actor": admin.principal_id, "now": store.now(clock)},
            )
        )


def retire_due_turns(db: Database, actor: ScheduledActor, clock: Clock) -> int:
    """The scheduled pass's retirement (#503): no actor in the database, the same thirty days.

    `assistant_turn_retire_due` measures the thirty days on the database's own clock and takes
    no time from its caller, so nothing a pass is handed can retire a turn early.
    """
    with db.transaction(actor.tenant_id) as conn:
        # `assistant_turn_retire_due` takes the tenant control lock itself, as
        # `assistant_turn_retire` does, so no fence is taken here.
        try:
            scheduled_check(conn, actor)
        except ExecutionError:
            raise AssistantError("INVALID_IDENTITY") from None
        return int(_call(conn, "SELECT execbound.assistant_turn_retire_due()", {}))


def set_tenant_switch(
    db: Database, admin: Identity, enabled: bool, reason: object, clock: Clock
) -> SwitchChange:
    """Turn the assistant on or off for the tenant; a no-op is refused, every change audited
    with its reason. The provider's retention is stated beside the switch by the page and
    the CLI, not stored here. The switch is the whole workspace's, so an administrator
    narrowed to spaces is refused it (`INVALID_IDENTITY`), since 8 October 2026."""
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise AssistantError("INVALID_REASON")
    if secret_shaped(reason):
        raise AssistantError("INVALID_REASON")
    if type(enabled) is not bool:
        raise AssistantError("INVALID_STATE")
    with db.transaction(admin.tenant_id) as conn:
        _check(conn, admin, clock, "ADMIN", workspace=True)
        store.fence(conn, admin.tenant_id, clock)
        _check(conn, admin, clock, "ADMIN", workspace=True)
        previous = tenant_switch(conn, admin.tenant_id)
        if previous == enabled:
            raise AssistantError("INVALID_STATE")
        changed_at = store.now(clock)
        conn.execute(
            text(
                "UPDATE execbound.tenant_policy_control SET assistant_enabled=:e WHERE tenant_id=:t"
            ),
            {"e": enabled, "t": admin.tenant_id},
        )
        append_event(
            conn,
            admin.tenant_id,
            admin.principal_id,
            "tenant.assistant_changed",
            {
                "previous": previous,
                "enabled": enabled,
                "reason": reason.strip(),
                "principal_id": str(admin.principal_id),
                "credential_id": str(admin.credential_id),
                # `credential_id` stays for the events already retained and their readers.
                **acted_with(admin.credential_id),
                "replay": {"version": 1, "semantic_time": changed_at.isoformat()},
            },
        )
        _check(conn, admin, clock, "ADMIN", workspace=True)
    return SwitchChange(previous=previous, enabled=enabled)
