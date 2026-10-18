# SPDX-License-Identifier: Apache-2.0
"""List the agent's actions or drive one through the MCP surface with the official Python SDK.

Seed and serve the demonstration first (see examples/README.md), then list the actions the
agent's space offers and request one:

    uv run python examples/mcp_agent.py --private local-data/demo-1 --list
    uv run python examples/mcp_agent.py --private local-data/demo-1 --target workstation-01 \\
        --action endpoint.isolate --key ticket-4712

The listing and the flow both live in the client package (the ``mcp`` extra), and every
call carries the bearer credential in its header. The gateway exposes three tools.
``--list`` calls ``list_actions`` through ``execbound_client.mcp.list_actions`` and prints
the listing it returns; a listed action is not permission, and every request is still
decided. A request goes through ``execbound_client.mcp.run_action``, which uses the other
two, ``execute`` and ``execution_status``: a pending approval is polled with the returned
continuation, then ``execute`` is called again with the same request to progress it. This
file is the command line around those two functions for the local demonstration.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from execbound_client import UNCERTAIN_STATES, action_request
from execbound_client.mcp import McpRefused, list_actions, run_action


def refused(refusal: McpRefused) -> int:
    print(json.dumps({"outcome": "refused", "tool": refusal.tool, "code": refusal.code}))
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--tenant", type=int, choices=(0, 1), default=0)
    parser.add_argument("--agent", default="agent-0")
    parser.add_argument(
        "--list", action="store_true", help="list the actions the agent's space offers"
    )
    parser.add_argument("--target")
    parser.add_argument("--action")
    parser.add_argument("--key")
    parser.add_argument("--wait", type=float, default=120.0)
    args = parser.parse_args(argv)
    acting = {"--target": args.target, "--action": args.action, "--key": args.key}
    if args.list and any(value is not None for value in acting.values()):
        parser.error("--list requests no action, so it takes no --target, --action or --key")
    missing = [flag for flag, value in acting.items() if value is None]
    if not args.list and missing:
        parser.error("the following arguments are required: " + ", ".join(missing))
    fixture = json.loads((args.private / "fixture.json").read_text(encoding="utf-8"))
    tenant = fixture["tenants"][args.tenant]
    actors = json.loads((args.private / "credentials.json").read_text(encoding="utf-8"))
    token = next(a for a in actors[tenant["tenant_id"]] if a["label"] == args.agent)["token"]
    origin = f"http://127.0.0.1:{fixture['ports']['gateway']}"
    if args.list:
        try:
            listing = asyncio.run(list_actions(origin, token))
        except McpRefused as refusal:
            return refused(refusal)
        print(json.dumps(listing, indent=2))
        return 0
    target = next(t for t in tenant["targets"] if t["label"] == args.target)
    request = action_request(
        args.action, "canonical", target["resource_id"], args.key, incident_id=target["incident_id"]
    )
    try:
        view = asyncio.run(run_action(origin, token, request, approval_wait_seconds=args.wait))
    except McpRefused as refusal:
        return refused(refusal)
    print(json.dumps(view, indent=2))
    if view["state"] in UNCERTAIN_STATES:
        print(
            "Uncertain outcome: do not resend; ask an administrator to reconcile.", file=sys.stderr
        )
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
