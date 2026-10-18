# SPDX-License-Identifier: AGPL-3.0-only
"""Send one synthetic fixture request without printing its private agent credential."""

import argparse
import asyncio
import json
from pathlib import Path

import httpx

from execbound_harness.validation_run import action_request, mcp_retry, private_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Send or retry one local synthetic action")
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--tenant", type=int, choices=(0, 1), default=0)
    parser.add_argument("--agent", choices=("agent-0", "agent-1"), default="agent-0")
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--action",
        choices=(
            "endpoint.isolate",
            "identity.disable",
            "identity.enable",
            "identity.revoke_sessions",
        ),
        required=True,
    )
    parser.add_argument("--key", required=True)
    parser.add_argument("--protocol", choices=("http", "mcp"), default="http")
    args = parser.parse_args()
    try:
        fixture = private_json(args.private / "fixture.json")
        tenant = fixture["tenants"][args.tenant]
        target = next(t for t in tenant["targets"] if t["label"] == args.target)
        credentials = private_json(args.private / "credentials.json")[tenant["tenant_id"]]
        actor = next(a for a in credentials if a["label"] == args.agent)
        port = fixture["ports"]["gateway"]
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError()
        origin = f"http://127.0.0.1:{port}"
        body = action_request(target, args.action, args.key)
        if args.protocol == "mcp":
            result = asyncio.run(mcp_retry(origin, actor["token"], body))
        else:
            with httpx.Client(trust_env=False, timeout=10) as client:
                response = client.post(
                    origin + "/v1/execute",
                    json=body,
                    headers={"Authorization": "Bearer " + actor["token"]},
                )
                response.raise_for_status()
                result = response.json()
        print(json.dumps(result, indent=2))
    except Exception:
        parser.exit(2, "Synthetic request unavailable.\n")


if __name__ == "__main__":
    main()
