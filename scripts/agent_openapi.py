# SPDX-License-Identifier: AGPL-3.0-only
"""Write the agent API's OpenAPI document, or check that the committed one is current.

The gateway serves no OpenAPI document; this one is published on the documentation site for
people building agents, and `--check` holds it to the models and the error table it is built
from, the way `scripts/console_openapi.py` holds the console's.

    uv run python scripts/agent_openapi.py            # write docs/api/agent-v1.json
    uv run python scripts/agent_openapi.py --check    # exit 1 when the file is not current
"""

import argparse
import json
import sys
from pathlib import Path

from execbound.surfaces.agent_openapi import agent_api_document

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "api" / "agent-v1.json"


def render() -> str:
    return json.dumps(agent_api_document(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    parser.add_argument("--output", type=Path, default=DOCUMENT)
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != text:
            print(f"{args.output} is not current; run scripts/agent_openapi.py", file=sys.stderr)
            return 1
        print(f"{args.output} is current")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(text.encode("utf-8"))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
