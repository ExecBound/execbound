# SPDX-License-Identifier: AGPL-3.0-only
"""The model loop: bounded, beside the request, failing rather than retrying past a bound.

One turn is one row and one loop. The loop sends the fixed prefix, the tools and the
conversation so far, runs each tool call the model makes under the person's session, writes
a step to the row as each read happens, and ends with the answer the renderer accepts or a
failure with its reason. Three bounds, each a reason: the tool-call count, the wall clock
and the output tokens. A provider error is retried once when it is the kind that passes,
inside the time bound, and never otherwise.
"""

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from execbound.assistant import ASKED, REFUSED
from execbound.assistant.client import (
    ModelError,
    Transport,
    Usage,
    build_request,
    parse_response,
)
from execbound.assistant.config import AssistantConfig
from execbound.assistant.prompts import FIXED_INSTRUCTIONS, catalog_digest
from execbound.assistant.render import ANSWER_SCHEMA, RenderError, parse_answer
from execbound.assistant.tools import SPECS, ToolContext, ToolError, run_tool
from execbound.assistant.turns import (
    AssistantError,
    Caps,
    Turn,
    append_step,
    complete_turn,
    create_turn,
    read_turn,
)
from execbound.audit import acted_with, append_event
from execbound.runtime import Runtime
from execbound.surfaces.sessions import Session

EXPLAIN_TOOL = {
    "execution": "get_execution",
    "approval": "get_approval",
    "finding": "list_findings",
    "agent": "get_agent",
    "policy_change": "get_policy",
}
EXPLAIN_ARGUMENT = {
    "execution": "execution_id",
    "approval": "approval_id",
    "agent": "agent_principal_id",
}


@dataclass(frozen=True)
class TurnOutcome:
    turn: Turn
    usage: Usage


def _opening(context_kind: str, context_id: UUID | None, question: str | None) -> str:
    if context_kind == "question":
        return f"Question from the person asking: {question}"
    what = context_kind.replace("_", " ")
    lines = [f"Explain the {what} with id {context_id} to the person asking, reading it first."]
    if question:
        lines.append(f"They add: {question}")
    return "\n".join(lines)


def _audit(runtime: Runtime, session: Session, kind: str, payload: dict[str, Any]) -> None:
    """One assistant event, naming the credential that asked: a browser session's own, or a
    personal access token's backing credential, which is the token one to one."""
    identity = session.identity
    attributed = {**payload, **acted_with(identity.credential_id)}
    with runtime.db.transaction(identity.tenant_id) as conn:
        append_event(conn, identity.tenant_id, identity.principal_id, kind, attributed)


def probe_context(runtime: Runtime, session: Session, context_kind: str, context_id: UUID) -> None:
    """Re-read the record a contextual turn is about, with the asking person's authority.

    The one check that must happen before a model sees anything: an id this person cannot
    read is refused here exactly as the page refuses it, and a secret in what was read ends
    the attempt rather than starting a turn that would fail on its first call.
    """
    tool = EXPLAIN_TOOL.get(context_kind)
    if tool is None:
        raise AssistantError("INVALID_CONTEXT")
    argument = EXPLAIN_ARGUMENT.get(context_kind)
    arguments = {argument: str(context_id)} if argument else {}
    try:
        probe = run_tool(ToolContext(runtime=runtime, session=session), tool, arguments)
    except ToolError as error:
        code = "REFUSED_SECRET" if error.code == "REFUSED_SECRET" else "INVALID_CONTEXT"
        raise AssistantError(code) from None
    if argument and not probe.data.get("found"):
        raise AssistantError("INVALID_TURN")


def start_turn(
    runtime: Runtime,
    config: AssistantConfig,
    session: Session,
    *,
    context_kind: str,
    context_id: UUID | None,
    question: str | None,
) -> Turn:
    """The row, under the caps and the tenant switch; nothing has been sent yet."""
    return create_turn(
        runtime.db,
        session.identity,
        context_kind=context_kind,
        context_id=context_id,
        question=question,
        model=config.model,
        clock=runtime.clock,
        caps=Caps(config.person_hourly_turns, config.tenant_daily_tokens),
    )


def run_turn(
    runtime: Runtime,
    config: AssistantConfig,
    transport: Transport,
    session: Session,
    turn: Turn,
    *,
    tools: Sequence[Any] = SPECS,
) -> TurnOutcome:
    """Run one turn to its end and record it; the row is the only state there is."""
    identity = session.identity
    context = ToolContext(runtime=runtime, session=session)
    approval_context = turn.context_kind == "approval"
    digest = catalog_digest(runtime.catalog.actions, tools)
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": _opening(turn.context_kind, turn.context_id, turn.question)}
    ]
    usage = Usage()
    seen_ids: set[str] = set()
    tool_names: list[str] = []
    rows = 0
    calls = 0
    started = time.monotonic()

    def fail(reason: str) -> TurnOutcome:
        complete_turn(
            runtime.db,
            identity,
            turn.turn_id,
            state="FAILED",
            reason=reason,
            tool_names=tool_names,
            usage=usage,
            clock=runtime.clock,
        )
        _audit(
            runtime,
            session,
            REFUSED,
            {"turn_id": str(turn.turn_id), "reason": reason, "tools": list(tool_names)},
        )
        return TurnOutcome(read_turn(runtime.db, identity, turn.turn_id, runtime.clock), usage)

    def send(body: dict[str, Any]) -> Any:
        """One provider call, retried once for the kinds that pass, inside the time bound."""
        for attempt in (1, 2):
            try:
                return parse_response(transport.send(body))
            except ModelError as error:
                if attempt == 2 or error.code not in ModelError.RETRYABLE:
                    raise
                if time.monotonic() - started > config.time_limit_seconds:
                    raise
        raise ModelError("MODEL_ERROR")

    while True:
        if time.monotonic() - started > config.time_limit_seconds:
            return fail("TIME_LIMIT")
        body = build_request(
            config,
            fixed_instructions=FIXED_INSTRUCTIONS,
            catalog_digest=digest,
            tools=tools,
            messages=messages,
            answer_schema=ANSWER_SCHEMA,
        )
        try:
            response = send(body)
        except ModelError as error:
            return fail("TIME_LIMIT" if error.code == "TIMEOUT" else "MODEL_ERROR")
        usage = usage + response.usage
        if usage.output_tokens > config.max_output_tokens or response.stop_reason == "max_tokens":
            return fail("TOKEN_LIMIT")
        if response.tool_calls:
            if time.monotonic() - started > config.time_limit_seconds:
                return fail("TIME_LIMIT")
            results: list[dict[str, Any]] = []
            for call in response.tool_calls:
                calls += 1
                if calls > config.max_tool_calls:
                    return fail("TOOL_LIMIT")
                try:
                    result = run_tool(context, call.name, call.arguments)
                except ToolError as error:
                    if error.code == "REFUSED_SECRET":
                        return fail("REFUSED_SECRET")
                    # An unknown tool or an argument the schema does not admit: the model
                    # hears the code, nothing is read, and the call counts against the bound.
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": call.id,
                            "content": error.code,
                            "is_error": True,
                        }
                    )
                    continue
                tool_names.append(result.name)
                rows += int(result.data.get("count", 1 if result.data.get("found") else 0))
                seen_ids.update(result.ids)
                append_step(runtime.db, identity, turn.turn_id, result.step, runtime.clock)
                results.append(
                    {"type": "tool_result", "tool_use_id": call.id, "content": _json(result.data)}
                )
            messages.append({"role": "assistant", "content": list(response.content)})
            messages.append({"role": "user", "content": results})
            continue
        if response.stop_reason != "end_turn":
            return fail("MODEL_ERROR")
        try:
            answer = parse_answer(response.text, seen_ids, approval_context=approval_context)
        except RenderError as error:
            return fail("RECOMMENDATION" if error.code == "RECOMMENDATION" else "MODEL_ERROR")
        cited = tuple(dict.fromkeys(value for p in answer.paragraphs for value in p.ids))
        complete_turn(
            runtime.db,
            identity,
            turn.turn_id,
            state="COMPLETED",
            answer={
                "paragraphs": [{"text": p.text, "ids": list(p.ids)} for p in answer.paragraphs],
                "cannot_answer": answer.cannot_answer,
            },
            cited_ids=cited,
            tool_names=tool_names,
            usage=usage,
            clock=runtime.clock,
        )
        _audit(
            runtime,
            session,
            ASKED,
            {
                "turn_id": str(turn.turn_id),
                "context_kind": turn.context_kind,
                "context_id": str(turn.context_id) if turn.context_id else None,
                "tools": list(tool_names),
                "rows": rows,
                "model": config.model,
                "input_tokens": usage.input_tokens,
                "cached_tokens": usage.cache_read_input_tokens,
                "output_tokens": usage.output_tokens,
                "cannot_answer": answer.cannot_answer,
            },
        )
        return TurnOutcome(read_turn(runtime.db, identity, turn.turn_id, runtime.clock), usage)


def _json(data: dict[str, Any]) -> str:
    import json

    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def ask(
    runtime: Runtime,
    config: AssistantConfig,
    transport: Transport,
    session: Session,
    question: str,
) -> TurnOutcome:
    """A free question: the row, then the loop, in the caller's thread."""
    turn = start_turn(
        runtime, config, session, context_kind="question", context_id=None, question=question
    )
    return run_turn(runtime, config, transport, session, turn)


def explain(
    runtime: Runtime,
    config: AssistantConfig,
    transport: Transport,
    session: Session,
    context_kind: str,
    context_id: UUID,
    *,
    question: str | None = None,
) -> TurnOutcome:
    """A contextual turn: the record is re-read with the person's authority before the
    model sees anything, so an id the person cannot read is refused as the page refuses it."""
    probe_context(runtime, session, context_kind, context_id)
    turn = start_turn(
        runtime,
        config,
        session,
        context_kind=context_kind,
        context_id=context_id,
        question=question,
    )
    return run_turn(runtime, config, transport, session, turn)
