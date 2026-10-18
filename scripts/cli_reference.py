# SPDX-License-Identifier: AGPL-3.0-only
"""Write the command-line reference, or check that the committed one is current.

The page is generated from the commands' own argument parsers (`execbound.cli_reference`),
so `--check` holds it to the commands the way `scripts/agent_openapi.py` holds the agent API
document to its models.

    uv run python scripts/cli_reference.py            # write docs/CLI_REFERENCE.md
    uv run python scripts/cli_reference.py --check    # exit 1 when the page is not current
"""

import argparse
import sys
from pathlib import Path

from execbound.cli_reference import render

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "CLI_REFERENCE.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    parser.add_argument("--output", type=Path, default=PAGE)
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != text:
            print(f"{args.output} is not current; run scripts/cli_reference.py", file=sys.stderr)
            return 1
        print(f"{args.output} is current")
        return 0
    args.output.write_bytes(text.encode("utf-8"))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
