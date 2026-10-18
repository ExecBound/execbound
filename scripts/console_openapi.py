# SPDX-License-Identifier: AGPL-3.0-only
"""Write the console API's OpenAPI documents, or check that the committed ones are current.

The console's generated client in `console/src/api` is produced from
`console/openapi/console-v1.json` by openapi-ts on every `pnpm` command that reads it, and is
not committed; this document is, and `--check` holds it to the router the way
`scripts/render_age_classes.py` and `tests/test_board_css.py` hold the stylesheet to its
generator. The document is built from the console API's router alone, never from the
application's, so the agent API never reaches the client (#333). The committed document is
core's own, the published console API.

Each `--plugin NAME` also writes the document of that plugin's own console areas to
`console/src/NAME/openapi/console-NAME-v1.json`, from which that plugin's console edition
generates its own client (#496).

    uv run python scripts/console_openapi.py [--check]
        # write core's document, or exit 1 when it is not current
    uv run python scripts/console_openapi.py --plugin NAME
        # write both documents
    uv run python scripts/console_openapi.py --plugin NAME --check
        # exit 1 when either is not current
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from execbound.plugins import load_plugins
from execbound.surfaces.console_api import console_api_document, plugin_console_document

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "console" / "openapi" / "console-v1.json"


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def plugin_document(name: str) -> Path:
    """Where a plugin's console edition reads its own document."""
    return ROOT / "console" / "src" / name / "openapi" / f"console-{name}-v1.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    parser.add_argument("--output", type=Path, help="write the core document here instead")
    parser.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="also write this plugin's own document, of its console areas alone",
    )
    args = parser.parse_args(argv)
    if args.plugin and args.output is not None:
        # `--output` moves the core document only, so a plugin's would still overwrite the
        # committed one at its repository path.
        parser.error("--output cannot be combined with --plugin")
    documents = {args.output or DOCUMENT: render(console_api_document())}
    for name in args.plugin:
        documents[plugin_document(name)] = render(
            plugin_console_document(load_plugins({name: None}))
        )
    if args.check:
        stale = [
            path
            for path, text in documents.items()
            if (path.read_text(encoding="utf-8") if path.exists() else "") != text
        ]
        for path in stale:
            print(
                f"{path} is not current; run scripts/console_openapi.py with the same arguments",
                file=sys.stderr,
            )
        if stale:
            return 1
        for path in documents:
            print(f"{path} is current")
        return 0
    for path, text in documents.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
