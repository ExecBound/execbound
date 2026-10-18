# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/assistant`: the console's assistant, or nothing at all.

The routes exist only when the private configuration carries an `assistant` block, so a
deployment that configured no model has no assistant addresses rather than addresses that
refuse; a tenant whose ADMIN has not turned it on has them and is refused `ASSISTANT_OFF`.
Every route takes the session and nothing else, and reads only the acting person's own turns:
an administrator cannot open an approver's question. A turn is created and answered at once;
the model loop runs as a background task in this process and writes each step to the row, and
`GET .../events` follows that row as server-sent events (#330).
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from execbound.assistant import EXPLAINED
from execbound.assistant.client import HttpTransport, Transport
from execbound.assistant.config import PROVIDER_RETENTION, AssistantConfig
from execbound.assistant.events import HEADERS, MEDIA_TYPE, turn_events
from execbound.assistant.loop import probe_context, run_turn, start_turn
from execbound.assistant.proposals import (
    MAX_WORDS,
    ProposalError,
    proposal_fields,
    propose_rule,
)
from execbound.assistant.turns import (
    AssistantError,
    Turn,
    list_turns,
    read_turn,
    set_tenant_switch,
    tenant_switch,
)
from execbound.audit import acted_with, append_event
from execbound.runtime import Runtime
from execbound.surfaces.console_api.directory import UUID_PATTERN, body_of, parse_uuid
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

QUESTION_LIMIT = 1000
REASON_LIMIT = 500
ContextKind = Literal["question", "execution", "approval", "finding", "agent", "policy_change"]

# What a turn's refusal is, as the closed list of API codes says it, and, for a body fault,
# its field. A code not listed here is the server's own trouble and reads as unavailability,
# never as something the person did.
REFUSALS: dict[str, tuple[str, list[str] | None]] = {
    "ASSISTANT_OFF": ("ASSISTANT_OFF", None),
    "PERSON_LIMIT": ("TOO_MANY_REQUESTS", None),
    "TENANT_LIMIT": ("TOO_MANY_REQUESTS", None),
    "INVALID_TURN": ("NOT_FOUND", None),
    "INVALID_IDENTITY": ("FORBIDDEN", None),
    "INVALID_ACTOR": ("FORBIDDEN", None),
    "INVALID_CONTEXT": ("INVALID_BODY", None),
    "INVALID_QUESTION": ("INVALID_BODY", None),
    # Only `set_tenant_switch` raises this, for its own reason screen; every other
    # caller of `refused()` can never produce it, so naming the field is exact everywhere.
    "INVALID_REASON": ("INVALID_BODY", ["reason"]),
    "INVALID_STATE": ("CONFLICT", None),
    "INVALID_BUNDLE": ("INVALID_BUNDLE", None),
}


class Paragraph(BaseModel):
    text: str
    ids: list[str]


class TurnView(BaseModel):
    turn_id: UUID
    context_kind: str
    context_id: UUID | None
    question: str | None
    state: str
    reason: str | None
    steps: list[str]
    paragraphs: list[Paragraph]
    cannot_answer: bool
    cited_ids: list[str]
    created_at: datetime
    completed_at: datetime | None


class TurnList(BaseModel):
    turns: list[TurnView]


class AskBody(BaseModel):
    """A question, a context, or both. The id is text here and parsed below, because a strict
    model takes no UUID from JSON and every other area of this API spells ids the same way."""

    model_config = ConfigDict(extra="forbid", strict=True)
    question: str | None = Field(default=None, min_length=1, max_length=QUESTION_LIMIT)
    context_kind: ContextKind = "question"
    context_id: str | None = Field(default=None, pattern=UUID_PATTERN)


class _Empty(BaseModel):
    """A body with nothing in it: the request is the act."""

    model_config = ConfigDict(extra="forbid", strict=True)


class DraftRuleBody(BaseModel):
    """Which draft, and what the person said. The words are theirs, bounded and stored as
    the turn's question; the draft is read with their own authority before the model sees
    anything about it."""

    model_config = ConfigDict(extra="forbid", strict=True)
    bundle_id: str = Field(pattern=UUID_PATTERN)
    words: str = Field(min_length=1, max_length=MAX_WORDS)


class ProposedCondition(BaseModel):
    kind: str
    name: str
    operator: str
    values: list[str | int | bool]


class ProposedRule(BaseModel):
    id: str
    action: str
    effect: str
    quorum: int | None
    note: str | None
    when: list[ProposedCondition]


class Proposed(BaseModel):
    """One rule the compiler accepted against the draft, as the add-a-rule form takes it.

    `sentence` is how it reads, `lines` are its conditions in the words the editor parses,
    and `rule` is the form's own shape. Nothing here has been written: the person submits it.
    """

    rule: ProposedRule
    sentence: str
    lines: list[str]
    words: str


class SwitchBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    enabled: bool
    reason: str = Field(min_length=1, max_length=REASON_LIMIT)


class Settings(BaseModel):
    enabled: bool
    model: str
    provider_retention: str
    person_hourly_turns: int
    tenant_daily_tokens: int


def refused(exc: AssistantError) -> ApiError:
    code, fields = REFUSALS.get(exc.code, ("UNAVAILABLE", None))
    return ApiError(code, fields=fields)


def view_of(turn: Turn) -> TurnView:
    answer = turn.answer or {}
    return TurnView(
        turn_id=turn.turn_id,
        context_kind=turn.context_kind,
        context_id=turn.context_id,
        question=turn.question,
        state=turn.state,
        reason=turn.reason,
        steps=list(turn.steps),
        paragraphs=[Paragraph.model_validate(item) for item in answer.get("paragraphs", [])],
        cannot_answer=bool(answer.get("cannot_answer", False)),
        cited_ids=list(turn.cited_ids),
        created_at=turn.created_at,
        completed_at=turn.completed_at,
    )


def _admin(session: Session) -> Session:
    if session.identity.kind != "ADMIN":
        raise ApiError("FORBIDDEN")
    return session


def assistant_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    if not config.assistant_enabled:
        # No block, no addresses: the feature is absent rather than disabled. The flag is
        # what the document generator can see, and it is set from the block itself.
        return

    def block() -> AssistantConfig:
        """The operator's configuration at request time; its absence here is our own fault."""
        assistant = runtime.assistant
        if assistant is None:
            raise ApiError("UNAVAILABLE")
        return assistant

    def transport() -> Transport:
        """The provider, or the scripted one a test put on the runtime."""
        scripted = runtime.assistant_transport
        return scripted if scripted is not None else HttpTransport(block())

    def read(session: Session, turn_id: UUID) -> Turn:
        return read_turn(
            runtime.db,
            session.identity,
            turn_id,
            runtime.clock,
            abandon_after_seconds=block().abandon_after_seconds,
        )

    @routes.post(
        "/assistant/turns",
        response_model=TurnView,
        operation_id="askAssistant",
        openapi_extra=body_of(AskBody),
    )
    async def ask(request: Request, background: BackgroundTasks) -> TurnView:
        session, body = await guards.mutation(request, AskBody)
        if (body.context_kind == "question") != (body.context_id is None):
            raise ApiError("INVALID_BODY", fields=["context_id"])
        if body.context_kind == "question" and not body.question:
            raise ApiError("INVALID_BODY", fields=["question"])
        context_id = parse_uuid(body.context_id, 400) if body.context_id is not None else None
        try:
            if context_id is not None:
                # The record is re-read with this person's authority before the model sees
                # anything, so an id they cannot read is refused as the page refuses it.
                await run_in_threadpool(
                    probe_context, runtime, session, body.context_kind, context_id
                )
            turn = await run_in_threadpool(
                start_turn,
                runtime,
                block(),
                session,
                context_kind=body.context_kind,
                context_id=context_id,
                question=body.question,
            )
        except AssistantError as exc:
            raise refused(exc) from None
        # The loop answers into the row; this response is the turn as it starts.
        background.add_task(_run, session, turn)
        return view_of(turn)

    def _run(session: Session, turn: Turn) -> None:
        """The loop, off the request. Its every ending is a row, so nothing is raised here."""
        try:
            run_turn(runtime, block(), transport(), session, turn)
        except AssistantError:
            return

    @routes.get("/assistant/turns", response_model=TurnList, operation_id="listAssistantTurns")
    async def list_own(request: Request) -> TurnList:
        session, _ = await guards.session(request)
        try:
            turns = await run_in_threadpool(list_turns, runtime.db, session.identity, runtime.clock)
        except AssistantError as exc:
            raise refused(exc) from None
        return TurnList(turns=[view_of(turn) for turn in turns])

    @routes.get(
        "/assistant/turns/{turn_id}", response_model=TurnView, operation_id="readAssistantTurn"
    )
    async def read_one(request: Request, turn_id: str) -> TurnView:
        session, _ = await guards.session(request)
        try:
            return view_of(await run_in_threadpool(read, session, parse_uuid(turn_id)))
        except AssistantError as exc:
            raise refused(exc) from None

    @routes.get(
        "/assistant/turns/{turn_id}/events",
        operation_id="streamAssistantTurn",
        response_class=StreamingResponse,
        responses={200: {"content": {MEDIA_TYPE: {"schema": {"type": "string"}}}}},
    )
    async def stream(request: Request, turn_id: str) -> StreamingResponse:
        session, _ = await guards.session(request)
        identifier = parse_uuid(turn_id)
        try:
            # Read once inside the request, so a turn that is not this person's refuses with
            # a status rather than opening a stream that says nothing.
            await run_in_threadpool(read, session, identifier)
        except AssistantError as exc:
            raise refused(exc) from None

        async def follow() -> Any:
            return await run_in_threadpool(read, session, identifier)

        return StreamingResponse(turn_events(follow), media_type=MEDIA_TYPE, headers=dict(HEADERS))

    @routes.post(
        "/assistant/turns/{turn_id}/opened",
        response_model=TurnView,
        operation_id="recordAssistantTurnOpened",
        openapi_extra=body_of(_Empty),
    )
    async def opened(request: Request, turn_id: str) -> TurnView:
        """A person opened a generated explanation. Recorded, so a later review can see which
        decisions were made after reading one."""
        session, _ = await guards.mutation(request, _Empty)
        identifier = parse_uuid(turn_id)
        try:
            turn = await run_in_threadpool(read, session, identifier)
        except AssistantError as exc:
            raise refused(exc) from None
        await run_in_threadpool(_explained, session, turn)
        return view_of(turn)

    def _explained(session: Session, turn: Turn) -> None:
        identity = session.identity
        with runtime.db.transaction(identity.tenant_id) as conn:
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                EXPLAINED,
                {
                    "turn_id": str(turn.turn_id),
                    "context_kind": turn.context_kind,
                    "context_id": str(turn.context_id) if turn.context_id else None,
                    "state": turn.state,
                    **acted_with(identity.credential_id),
                },
            )

    @routes.post(
        "/assistant/rules",
        response_model=Proposed,
        operation_id="draftAssistantRule",
        openapi_extra=body_of(DraftRuleBody),
    )
    async def draft_rule(request: Request) -> Proposed:
        """Draft one rule for a draft from a person's own words, and write nothing.

        The answer is a pre-filled form: the administrator reads it beside what they said and
        submits it themselves through the rules page, and the draft then goes through
        validation and preview like any other. A proposal the compiler will not accept is
        refused here, naming the field, rather than offered and failing later.
        """
        session, body = await guards.mutation(request, DraftRuleBody)
        _admin(session)
        try:
            proposal = await run_in_threadpool(
                propose_rule,
                runtime,
                block(),
                transport(),
                session,
                parse_uuid(body.bundle_id, 400),
                body.words,
            )
        except ProposalError as exc:
            raise ApiError("INVALID_PROPOSAL", fields=list(exc.locations)[:8]) from None
        except AssistantError as exc:
            raise refused(exc) from None
        return Proposed(
            rule=ProposedRule.model_validate(dict(proposal_fields(proposal))),
            sentence=proposal.sentence,
            lines=list(proposal.lines),
            words=body.words,
        )

    @routes.get(
        "/assistant/settings", response_model=Settings, operation_id="readAssistantSettings"
    )
    async def read_settings(request: Request) -> Settings:
        session, _ = await guards.session(request)
        _admin(session)
        return await run_in_threadpool(_settings, session, block())

    def _settings(session: Session, block: AssistantConfig) -> Settings:
        tenant = session.identity.tenant_id
        with runtime.db.transaction(tenant) as conn:
            enabled = tenant_switch(conn, tenant)
        return Settings(
            enabled=enabled,
            model=block.model,
            provider_retention=PROVIDER_RETENTION,
            person_hourly_turns=block.person_hourly_turns,
            tenant_daily_tokens=block.tenant_daily_tokens,
        )

    @routes.post(
        "/assistant/settings",
        response_model=Settings,
        operation_id="setAssistantSettings",
        openapi_extra=body_of(SwitchBody),
    )
    async def set_settings(request: Request) -> Settings:
        session, body = await guards.mutation(request, SwitchBody)
        _admin(session)
        try:
            await run_in_threadpool(
                set_tenant_switch,
                runtime.db,
                session.identity,
                body.enabled,
                body.reason,
                runtime.clock,
            )
        except AssistantError as exc:
            raise refused(exc) from None
        return await run_in_threadpool(_settings, session, block())
