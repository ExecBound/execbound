# SPDX-License-Identifier: AGPL-3.0-only
"""Actual maintained v1 SDK, isolated from the installed v2 runtime dependencies."""

import asyncio
import json
import site
import sys
from pathlib import Path

target = Path(__file__).resolve().parents[1] / ".tools" / "mcp-legacy"
if not (target / "mcp").is_dir():
    raise RuntimeError("Install tests/mcp-legacy.txt into .tools/mcp-legacy before verification")
sys.path.insert(0, str(target))
site.addsitedir(str(target))

import httpx  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402


async def main():
    config = json.load(sys.stdin)
    async with httpx.AsyncClient(
        headers={"Authorization": "Bearer " + config["token"]}, trust_env=False
    ) as http:
        async with streamable_http_client(config["url"], http_client=http) as (read, write, _):
            async with ClientSession(read, write) as client:
                initialized = await client.initialize()
                listing = await client.list_tools()
                result = await client.call_tool("execute", {"request": config["request"]})
                first = result.structuredContent
                again = await client.call_tool("execute", {"request": config["request"]})
                http.headers["Authorization"] = "Bearer " + config["other_token"]
                foreign = await client.call_tool(
                    "execution_status", {"execution_id": first["execution_id"]}
                )
                print(
                    json.dumps(
                        {
                            "protocol": initialized.protocolVersion,
                            "tools": [tool.name for tool in listing.tools],
                            "first": first,
                            "retry": again.structuredContent,
                            "foreign_error": foreign.isError,
                            "foreign": foreign.structuredContent,
                        }
                    )
                )


if __name__ == "__main__":
    asyncio.run(main())
