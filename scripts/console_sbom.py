# SPDX-License-Identifier: AGPL-3.0-only
"""A CycloneDX SBOM for the console's npm tree, from the lockfile, and the licence allowlist.

The lockfile is the input the install resolved from, so a bill of materials read from it lists
what shipped rather than what a developer's `node_modules` happens to hold, and it needs no
tool beyond this file. `pnpm licenses list --json` supplies each package's licence; the
production list (`--prod`) says which packages the browser receives. Every production package
must carry an allowed licence; a development package may instead be named as an exception in
`console/DEPENDENCIES.md`, with its reason
(#333).

Nothing here claims a signature or a registry digest; the hashes are the lockfile's own
integrity values, which pnpm verified against the registry when it installed.
"""

import argparse
import base64
import fnmatch
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# The allowlist (MIT, Apache-2.0, the BSD family, ISC) and the dedications that oblige
# strictly less than MIT does: MIT without its attribution clause, and the public-domain forms.
ALLOWED = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "MIT-0",
        "Unlicense",
        "CC0-1.0",
    }
)
PACKAGE = re.compile(r"^  '?(?P<name>@?[^@']+)@(?P<version>[^'(]+)'?:\s*$")
INTEGRITY = re.compile(r"integrity:\s*(?P<algorithm>sha\d+)-(?P<digest>[A-Za-z0-9+/=]+)")
NAME = re.compile(r"`([^`]+)`")
IDENTIFIER = re.compile(r"[A-Za-z0-9.+-]+")


def packages(lockfile: Path) -> list[dict[str, str]]:
    """Every resolved package of the lockfile's `packages:` section with its integrity."""
    found: list[dict[str, str]] = []
    inside = False
    current: dict[str, str] | None = None
    for line in lockfile.read_text(encoding="utf-8").splitlines():
        if line == "packages:":
            inside = True
            continue
        if inside and line and not line.startswith(" "):
            break
        if not inside:
            continue
        match = PACKAGE.match(line)
        if match:
            current = {"name": match.group("name"), "version": match.group("version")}
            found.append(current)
            continue
        integrity = INTEGRITY.search(line)
        if integrity and current is not None:
            current["algorithm"] = integrity.group("algorithm")
            current["digest"] = base64.b64decode(integrity.group("digest")).hex()
        if current is not None and line.startswith(("    os:", "    cpu:", "    libc:")):
            # A build for one platform: the install on any other leaves it out of the tree,
            # so the listing cannot know its licence and it took no part in the build.
            current["platform"] = "true"
    return found


def licences(listing: Path) -> dict[tuple[str, str], str]:
    """(name, version) to licence, from `pnpm licenses list --json`."""
    document = json.loads(listing.read_text(encoding="utf-8"))
    found: dict[tuple[str, str], str] = {}
    for licence, entries in document.items():
        for entry in entries:
            for version in entry.get("versions", []):
                found[(entry["name"], version)] = str(licence)
    return found


def exceptions(dependencies: Path) -> set[str]:
    """Package names, or `name-*` patterns, the document's licence exceptions section names."""
    names: set[str] = set()
    inside = False
    for line in dependencies.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            inside = line == "## Licence exceptions"
            continue
        if inside and line.startswith("- "):
            # Every backticked name before the colon; the rest of the line is the reason.
            names.update(NAME.findall(line.split(":", 1)[0]))
    return names


def allowed(expression: str) -> bool:
    """Whether a licence string is inside the allowlist.

    An `OR` expression is allowed when any of its identifiers is; anything else needs every
    identifier allowed, so `AND` and a bare identifier read the same way.
    """
    identifiers = [
        token
        for token in IDENTIFIER.findall(expression)
        if token.upper() not in {"AND", "OR", "WITH"}
    ]
    if not identifiers:
        return False
    if re.search(r"\bOR\b", expression):
        return any(token in ALLOWED for token in identifiers)
    return all(token in ALLOWED for token in identifiers)


def findings(
    resolved: list[dict[str, str]],
    known: dict[tuple[str, str], str],
    production: set[str],
    excepted: set[str],
) -> list[str]:
    """One sentence per package that breaks the allowlist."""
    problems: list[str] = []
    for package in resolved:
        name, version = package["name"], package["version"]
        licence = known.get((name, version))
        if licence is None:
            if package.get("platform") != "true":
                problems.append(f"{name}@{version} declares no licence the listing knows")
            continue
        if allowed(licence):
            continue
        if name in production:
            problems.append(f"{name}@{version} ships to the browser under {licence}")
        elif not any(fnmatch.fnmatchcase(name, pattern) for pattern in excepted):
            problems.append(
                f"{name}@{version} is {licence} and is not named in DEPENDENCIES.md's exceptions"
            )
    return problems


def bom(
    resolved: list[dict[str, str]], known: dict[tuple[str, str], str], revision: str
) -> dict[str, Any]:
    components = []
    for package in sorted(resolved, key=lambda p: (p["name"], p["version"])):
        component: dict[str, Any] = {
            "type": "library",
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:npm/{package['name']}@{package['version']}",
        }
        if "digest" in package:
            component["hashes"] = [
                {
                    "alg": package["algorithm"].upper().replace("SHA", "SHA-"),
                    "content": package["digest"],
                }
            ]
        if package.get("platform") == "true":
            component["properties"] = [{"name": "execbound:platform-specific", "value": "true"}]
        licence = known.get((package["name"], package["version"]))
        if licence is not None:
            key = "expression" if re.search(r"\b(AND|OR|WITH)\b", licence) else "id"
            component["licenses"] = (
                [{key: licence}] if key == "expression" else [{"license": {"id": licence}}]
            )
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "component": {
                "type": "application",
                "name": "execbound-console",
                "version": revision or "unknown",
            },
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--licenses", type=Path, required=True, help="pnpm licenses list --json")
    parser.add_argument(
        "--production-licenses", type=Path, required=True, help="pnpm licenses list --prod --json"
    )
    parser.add_argument("--dependencies", type=Path, required=True, help="console/DEPENDENCIES.md")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", default="")
    args = parser.parse_args(argv)
    resolved = packages(args.lockfile)
    known = licences(args.licenses)
    production = {name for name, _ in licences(args.production_licenses)}
    problems = findings(resolved, known, production, exceptions(args.dependencies))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(bom(resolved, known, args.revision), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"{len(resolved)} packages written to {args.output}")
    for problem in problems:
        print(f"licence: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
