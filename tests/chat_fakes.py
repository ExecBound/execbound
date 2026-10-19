# SPDX-License-Identifier: AGPL-3.0-only
"""Local stand-ins for a Slack incoming webhook and a Teams Workflows trigger.

Nothing here reaches a real host. Each fake checks the content type and the payload shape
the real service expects, records what it received, and answers with the next scripted
status (and `Retry-After`), so a test can drive 200, 202, 429, 404 and 500.

A finding message (#31) has a shape of its own, which each fake accepts beside the approval's.
"""

import json
import socket
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

SLACK_PATH = "/services/T0000TEST/B0000TEST/fakeWebhookPath000"
TEAMS_PATH = "/workflows/0a1b2c3d/triggers/manual/paths/invoke"
TEAMS_QUERY = "api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=fake-signature"
ADAPTIVE = "application/vnd.microsoft.card.adaptive"


@dataclass
class ChatFake:
    origin: str
    received: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    script: deque[tuple[int, dict[str, str]]] = field(default_factory=deque)

    @property
    def slack_url(self) -> str:
        return self.origin + SLACK_PATH

    @property
    def teams_url(self) -> str:
        return f"{self.origin}{TEAMS_PATH}?{TEAMS_QUERY}"

    def answer(self, status: int, **headers: str) -> None:
        self.script.append((status, headers))


def _plain(value: Any) -> bool:
    return isinstance(value, dict) and value.get("type") == "plain_text" and "text" in value


def _facts_ok(blocks: Any) -> bool:
    """A card's facts: one FactSet, or, where a workspace or Space name is one Teams could
    format, one RichTextBlock per fact holding a bold title run and the value's run."""
    if [block["type"] for block in blocks] == ["FactSet"]:
        return True
    return bool(blocks) and all(
        block["type"] == "RichTextBlock"
        and [run["type"] for run in block["inlines"]] == ["TextRun", "TextRun"]
        and block["inlines"][0]["weight"] == "Bolder"
        for block in blocks
    )


def _line_ok(block: Any) -> bool:
    """A line of a card: a TextBlock, or the RichTextBlock of one TextRun that carries a name
    Teams could format."""
    return block["type"] == "TextBlock" or (
        block["type"] == "RichTextBlock"
        and [run["type"] for run in block["inlines"]] == ["TextRun"]
    )


def slack_shape_ok(body: Any) -> bool:
    """The blocks the transport promises, every text object `plain_text`, two url buttons.

    The second button and the first context line are the basic-page footer of #333: the
    classic approval page for a phone whose console does not load.
    """
    try:
        header, section, actions, footer, context = body["blocks"]
        [button, basic] = actions["elements"]
        return (
            set(body) == {"text", "blocks"}
            and isinstance(body["text"], str)
            and header["type"] == "header"
            and _plain(header["text"])
            and section["type"] == "section"
            # Slack takes at most ten section fields; a message carries four to nine (#678).
            and 4 <= len(section["fields"]) <= 10
            and all(_plain(item) for item in section["fields"])
            and actions["type"] == "actions"
            and all(
                item["type"] == "button" and _plain(item["text"]) and item["url"].startswith("http")
                for item in (button, basic)
            )
            and basic["url"] == button["url"] + "/classic"
            and footer["type"] == "context"
            and context["type"] == "context"
            and all(_plain(item) for item in footer["elements"] + context["elements"])
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def teams_shape_ok(body: Any) -> bool:
    """The Workflows `message` envelope with one Adaptive Card and two open-URL actions.

    The second action and the third text block are the basic-page footer of #333.
    """
    try:
        [attachment] = body["attachments"]
        card = attachment["content"]
        [action, basic] = card["actions"]
        header, *facts, footer, context = card["body"]
        return (
            body["type"] == "message"
            and attachment["contentType"] == ADAPTIVE
            and card["type"] == "AdaptiveCard"
            and card["version"] == "1.4"
            and [item["type"] for item in (header, footer, context)] == ["TextBlock"] * 3
            and _facts_ok(facts)
            and all(
                item["type"] == "Action.OpenUrl" and item["url"].startswith("http")
                for item in (action, basic)
            )
            and basic["url"] == action["url"] + "/classic"
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def finding_slack_shape_ok(body: Any) -> bool:
    """A finding's blocks (#31): a header, two to four facts (a workspace or Space name nothing
    of which survives `name_label` is left out), the fixed sentence, one link button and two
    context lines, every text object `plain_text`."""
    try:
        header, facts, sentence, actions, choose, context = body["blocks"]
        [button] = actions["elements"]
        return (
            set(body) == {"text", "blocks"}
            and isinstance(body["text"], str)
            and header["type"] == "header"
            and _plain(header["text"])
            and facts["type"] == "section"
            and 2 <= len(facts["fields"]) <= 4
            and all(_plain(item) for item in facts["fields"])
            and sentence["type"] == "section"
            and _plain(sentence["text"])
            and actions["type"] == "actions"
            and button["type"] == "button"
            and _plain(button["text"])
            and button["url"].startswith("http")
            and all(
                block["type"] == "context" and all(_plain(item) for item in block["elements"])
                for block in (choose, context)
            )
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def finding_teams_shape_ok(body: Any) -> bool:
    """A finding's Workflows message: one Adaptive Card, its facts, three lines and one
    open-URL action."""
    try:
        [attachment] = body["attachments"]
        card = attachment["content"]
        [action] = card["actions"]
        header, *facts, sentence, choose, context = card["body"]
        return (
            body["type"] == "message"
            and attachment["contentType"] == ADAPTIVE
            and card["type"] == "AdaptiveCard"
            and card["version"] == "1.4"
            and [item["type"] for item in (header, sentence, context)] == ["TextBlock"] * 3
            and _facts_ok(facts)
            and _line_ok(choose)
            and action["type"] == "Action.OpenUrl"
            and action["url"].startswith("http")
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def slack_texts(body: Any) -> list[dict[str, Any]]:
    """Every Slack text object in a message's blocks, wherever it is nested."""
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") in {"plain_text", "mrkdwn"} and "text" in node:
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(body["blocks"])
    return found


def teams_texts(body: Any) -> tuple[list[str], list[str]]:
    """A card's strings Teams reads as Markdown (text blocks, facts and action titles), and the
    ones it shows as written (text runs)."""
    card = body["attachments"][0]["content"]
    parsed: list[str] = [action["title"] for action in card["actions"]]
    literal: list[str] = []
    for block in card["body"]:
        if block["type"] == "TextBlock":
            parsed.append(block["text"])
        elif block["type"] == "FactSet":
            for fact in block["facts"]:
                parsed += [fact["title"], fact["value"]]
        elif block["type"] == "RichTextBlock":
            for run in block["inlines"]:
                assert run["type"] == "TextRun"
                literal.append(run["text"])
        else:
            raise AssertionError(block["type"])
    return parsed, literal


def _app(state: ChatFake) -> FastAPI:
    app = FastAPI()

    async def receive(kind: str, request: Request, default: int) -> Response:
        raw = await request.body()
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        shaped = (
            slack_shape_ok(body) or finding_slack_shape_ok(body)
            if kind == "slack"
            else teams_shape_ok(body) or finding_teams_shape_ok(body)
        )
        if request.headers.get("content-type") != "application/json" or not shaped:
            state.refused.append(kind)
            return Response(status_code=400)
        state.received.append((kind, body))
        status, headers = state.script.popleft() if state.script else (default, {})
        return Response(status_code=status, headers=headers)

    @app.post(SLACK_PATH)
    async def slack(request: Request) -> Response:
        return await receive("slack", request, 200)

    @app.post(TEAMS_PATH)
    async def teams(request: Request) -> Response:
        return await receive("teams", request, 202)

    return app


@contextmanager
def chat_fake() -> Iterator[ChatFake]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        state = ChatFake(f"http://127.0.0.1:{sock.getsockname()[1]}")
        server = uvicorn.Server(uvicorn.Config(_app(state), log_level="critical", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started, "Chat fake did not become ready"
        try:
            yield state
        finally:
            server.should_exit = True
            thread.join(timeout=10)
