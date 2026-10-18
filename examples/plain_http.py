# SPDX-License-Identifier: Apache-2.0
"""Run one action against the local demonstration over plain HTTP, handling approval.

Seed and serve the demonstration first (see examples/README.md), then:

    uv run python examples/plain_http.py --private local-data/demo-1 --target workstation-01 \\
        --action endpoint.isolate --key ticket-4711

The idempotency key identifies the intended action; rerunning with the same key
retrieves or progresses the same execution instead of acting twice.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from execbound_client import ExecBoundClient, ExecBoundError, ExecBoundUncertain, action_request


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--private", type=Path, required=True, help="Fixture directory")
    parser.add_argument("--tenant", type=int, choices=(0, 1), default=0)
    parser.add_argument("--agent", default="agent-0")
    parser.add_argument("--target", required=True, help="Target label from fixture.json")
    parser.add_argument("--action", required=True)
    parser.add_argument("--key", required=True, help="Idempotency key for this intended action")
    parser.add_argument("--wait", type=float, default=120.0, help="Seconds to wait for approval")
    args = parser.parse_args()

    fixture = json.loads((args.private / "fixture.json").read_text(encoding="utf-8"))
    tenant = fixture["tenants"][args.tenant]
    target = next(t for t in tenant["targets"] if t["label"] == args.target)
    actors = json.loads((args.private / "credentials.json").read_text(encoding="utf-8"))
    token = next(a for a in actors[tenant["tenant_id"]] if a["label"] == args.agent)["token"]
    origin = f"http://127.0.0.1:{fixture['ports']['gateway']}"

    request = action_request(
        args.action, "canonical", target["resource_id"], args.key, incident_id=target["incident_id"]
    )
    client = ExecBoundClient(origin, token)
    try:
        outcome = client.run_to_completion(request, approval_wait_seconds=args.wait)
    except ExecBoundUncertain as uncertain:
        print(json.dumps({"outcome": "uncertain", **uncertain.view}, indent=2))
        print("Do not resend. Ask an administrator to reconcile this execution.", file=sys.stderr)
        return 3
    except ExecBoundError as refused:
        print(json.dumps({"outcome": "refused", "status": refused.status, "code": refused.code}))
        return 2
    finally:
        client.close()
    print(json.dumps({"outcome": outcome.state, "polls": outcome.polls, **outcome.view}, indent=2))
    if outcome.state == "PENDING_APPROVAL":
        print(
            "Still pending. Approve it at the approval URL, then rerun with the same key.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
