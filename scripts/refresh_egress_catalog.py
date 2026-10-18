# SPDX-License-Identifier: AGPL-3.0-only
"""Rewrite the egress catalog's feed ranges from feed files a person downloaded (#355).

OpenAI publishes its egress only as two JSON feeds, and Power Automate and Logic Apps use the
`AzureConnectors` service tag in Microsoft's weekly service tag download. The catalog's entries
for them take their networks from `src/execbound/monitoring/egress_feeds.py`, which this script
writes. Nothing here fetches anything, and the collector never does: download the files from the
sources `src/execbound/monitoring/egress.py` names, run this, review the diff and open a pull
request with it.

    uv run python scripts/refresh_egress_catalog.py --retrieved 2026-10-20 \\
        --openai-feed chatgpt-connectors.json --openai-feed chatgpt-agents.json \\
        --service-tags ServiceTags_Public_20261019.json
        # rewrite the module; a feed not given keeps what the module holds
    uv run python scripts/refresh_egress_catalog.py --retrieved 2026-10-20 ... --check
        # exit 1 when the module is not what these files would write

Each file is parsed whole and every network checked as the catalog checks an entry's; the
rewritten catalog is built before anything is written, so a feed that overlaps another
platform's ranges, holds a private or reserved range, or cannot be read refuses the refresh.
"""

import argparse
import sys
from datetime import date
from pathlib import Path

from execbound.monitoring import egress, egress_feeds

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "execbound" / "monitoring" / "egress_feeds.py"


def feeds_of(module: Path, source: str) -> dict[str, egress_feeds.Feed]:
    """The feeds the module being rewritten holds, read by running its source, as `egress_feeds`'
    own `Feed` values: a feed not given keeps what this module holds, which need not be what the
    installed package's does."""
    namespace: dict[str, object] = {"__name__": "egress_feeds_refreshed"}
    exec(compile(source, str(module), "exec"), namespace)  # the reviewed module being rewritten
    found = namespace.get("FEEDS")
    if not isinstance(found, dict):
        raise egress.CatalogError("feeds")
    return {
        str(key): egress_feeds.Feed(feed.retrieved, tuple(feed.networks))
        for key, feed in found.items()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--retrieved", type=date.fromisoformat, required=True)
    parser.add_argument("--openai-feed", type=Path, action="append", default=[])
    parser.add_argument("--service-tags", type=Path)
    parser.add_argument("--module", type=Path, default=MODULE, help="the module to rewrite")
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args(argv)
    if not args.openai_feed and args.service_tags is None:
        parser.error("give --openai-feed or --service-tags")
    current = args.module.read_text(encoding="utf-8")
    try:
        written = egress.refresh(
            current,
            retrieved=args.retrieved,
            existing=feeds_of(args.module, current),
            openai=[path.read_bytes() for path in args.openai_feed],
            service_tags=args.service_tags.read_bytes() if args.service_tags else None,
        )
    except egress.CatalogError as error:
        print(f"Refused: {error}", file=sys.stderr)
        return 2
    if args.check:
        return 0 if written == current else 1
    args.module.write_text(written, encoding="utf-8")
    print(f"wrote {args.module}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
