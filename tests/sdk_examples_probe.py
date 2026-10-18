# SPDX-License-Identifier: AGPL-3.0-only
"""Run one of the agent SDK tool examples against a real gateway with a scripted model.

The examples in clients/python/examples/ are what an engineer copies, so this runs them as
written: the module is imported unchanged and its tool is reached through the SDK's own
machinery. Only the model is replaced, by a script that makes the calls it is given in order
(the test lists the space's actions, then asks for an action, the same action again, and one
for a host the inventory does not hold) and then answers. The SDKs come from
.tools/sdk-examples (tests/sdk-examples.txt), kept apart from the runtime environment.

While the calls run, a heartbeat ticks on the event loop the tools run on, and the report
carries the longest the loop went without a tick: a tool that blocks the loop while a person
decides a held action stalls everything else the agent hosting it is doing.

Reads {"sdk", "url", "token", "calls"} as JSON on standard input, each call a {"tool",
"arguments"} pair naming one of the example's tools, and prints {"sdk", "version", "tools",
"results", "stall"}, one parsed tool summary per call and the longest gap in seconds.
"""

import asyncio
import contextlib
import importlib.util
import json
import os
import site
import sys
import time
from collections.abc import AsyncIterator
from importlib.metadata import version
from itertools import pairwise
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".tools" / "sdk-examples"
if not (TARGET / "agents").is_dir() or not (TARGET / "claude_agent_sdk").is_dir():
    raise RuntimeError(
        "Install tests/sdk-examples.txt into .tools/sdk-examples before verification"
    )
sys.path.insert(0, str(TARGET))
site.addsitedir(str(TARGET))
EXAMPLES = ROOT / "clients" / "python" / "examples"


def load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.asynccontextmanager
async def heartbeat() -> AsyncIterator[list[float]]:
    """Tick on the running loop for as long as the block runs; the times it yields, closed by
    the block's end, show the longest the loop stood still."""
    ticks = [time.monotonic()]

    async def tick() -> None:
        while True:
            await asyncio.sleep(0.05)
            ticks.append(time.monotonic())

    ticker = asyncio.create_task(tick())
    try:
        yield ticks
    finally:
        ticker.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ticker
        ticks.append(time.monotonic())


def longest_gap(ticks: list[float]) -> float:
    return round(max(later - earlier for earlier, later in pairwise(ticks)), 3)


async def openai_agents(calls: list[dict[str, Any]]) -> dict[str, Any]:
    from agents import RunConfig, Runner
    from agents.items import ModelResponse, ToolCallOutputItem
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import (
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )

    example = load("openai_agents_tool")

    class ScriptedModel(Model):
        """Each turn asks for the next scripted call; after the last, it answers."""

        def __init__(self) -> None:
            self.turn = 0
            self.tools: list[str] = []

        async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
            tools = kwargs.get("tools", args[3] if len(args) > 3 else [])
            self.tools = [tool.name for tool in tools]
            turn, self.turn = self.turn, self.turn + 1
            if turn < len(calls):
                item: Any = ResponseFunctionToolCall(
                    type="function_call",
                    id=f"fc_{turn}",
                    call_id=f"call_{turn}",
                    name=calls[turn]["tool"],
                    arguments=json.dumps(calls[turn]["arguments"]),
                    status="completed",
                )
            else:
                text = ResponseOutputText(type="output_text", text="done", annotations=[])
                item = ResponseOutputMessage(
                    type="message",
                    id="msg_final",
                    role="assistant",
                    status="completed",
                    content=[text],
                )
            return ModelResponse(output=[item], usage=Usage(), response_id=None)

        def stream_response(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError("the scripted model does not stream")

    model = ScriptedModel()
    async with heartbeat() as ticks:
        result = await Runner.run(
            example.agent,
            "Work the case.",
            run_config=RunConfig(model=model, tracing_disabled=True),
        )
    outputs = [item.output for item in result.new_items if isinstance(item, ToolCallOutputItem)]
    return {
        "version": version("openai-agents"),
        "tools": model.tools,
        "results": outputs,
        "stall": longest_gap(ticks),
    }


async def claude_agent_sdk(calls: list[dict[str, Any]]) -> dict[str, Any]:
    from mcp import Client

    example = load("claude_agent_sdk_tool")
    outputs = []
    # The SDK hosts the tool on an in-process MCP server that Claude Code reaches over an
    # in-memory transport; the scripted model reaches it the same way.
    async with Client(example.server["instance"]) as client:
        listing = await client.list_tools()
        async with heartbeat() as ticks:
            for call in calls:
                result = await client.call_tool(call["tool"], call["arguments"])
                assert not result.is_error, result
                outputs.append(result.content[0].text)
    return {
        "version": version("claude-agent-sdk"),
        "tools": [tool.name for tool in listing.tools],
        "results": outputs,
        "stall": longest_gap(ticks),
    }


def main() -> None:
    config = json.load(sys.stdin)
    os.environ["EXECBOUND_URL"] = config["url"]
    os.environ["EXECBOUND_CREDENTIAL"] = config["token"]
    os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "1"
    run = {"openai-agents": openai_agents, "claude-agent-sdk": claude_agent_sdk}[config["sdk"]]
    report = asyncio.run(run(config["calls"]))
    report["results"] = [json.loads(text) for text in report["results"]]
    print(json.dumps({"sdk": config["sdk"], **report}))


if __name__ == "__main__":
    main()
