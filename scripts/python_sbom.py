# SPDX-License-Identifier: AGPL-3.0-only
"""A CycloneDX SBOM for the Python runtime tree, from uv.lock, and the license allowlist.

The set of distributions comes from `uv.lock`, walked from the project's own dependencies
through the extras the lock resolved, so it is what a release installs rather than what a
developer's environment happens to hold. Each distribution's license comes from its
installed metadata, because that is the copy that ships: `License-Expression` (PEP 639)
first, then a `License` field that is itself an SPDX expression. A `License` field naming a
family rather than a license, such as "BSD License", is not read as one.

Every runtime distribution must carry a license on the allowlist that
#122 names: MIT, the BSD family, the
PSF license, Apache-2.0 and the dedications that oblige less. A distribution whose license
obliges more may instead be named in `DEPENDENCIES.md` under "License exceptions", with the
obligation written out. Strong copyleft is refused even there, because #122's inventory
records that the tree has no GPL-only dependency and that is a property to keep rather than
a default to wave through.

A distribution the environment cannot install on this platform (a Windows or Emscripten
wheel) has no installed metadata to read, so it is named in its own section of the document
rather than passed over. ExecBound's own packages, installed from the working tree, are named
in a section of their own, "First-party distributions", and one whose installed metadata
declares no license must be named there.

The hash recorded for a component is the lockfile's own: the sdist's where the lock has one,
and otherwise a single wheel's. A distribution the lock resolves to many wheels gets none,
because no one wheel digest describes the component that was installed.
"""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import re
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# #122's allowlist, in SPDX identifiers: MIT, the BSD family, the PSF license, Apache-2.0,
# and the dedications that oblige strictly less than MIT does.
ALLOWED = frozenset(
    {
        "MIT",
        "MIT-0",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "PSF-2.0",
        "Python-2.0",
        "Unlicense",
        "CC0-1.0",
    }
)
# Never excepted. An exception is for a notice obligation a distributor can meet by shipping
# a license text; these ask for the source of a combined work, which is a license decision
# and not a line in a dependency document.
REFUSED = re.compile(r"\b(?:A?GPL-[0-9.]+[A-Za-z-]*|SSPL-[0-9.]+|BUSL-[0-9.]+)\b")
# An SPDX expression: identifiers joined by AND, OR or WITH. "BSD License" is not one.
EXPRESSION = re.compile(r"^[A-Za-z0-9.+-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+-]+)*$")
IDENTIFIER = re.compile(r"[A-Za-z0-9.+-]+")
NAME = re.compile(r"`([^`]+)`")
ROW = re.compile(r"^\| `([^`]+)` \| ([^|]+?) \| ([^|]+?) \|\s*$")
SECTION = re.compile(r"^## (.+)$")
TABLE = "Runtime distributions"
# What the document's license column says where there is no license to record. It is not an
# SPDX identifier, so the SBOM leaves the component's license out rather than naming it.
NONE_DECLARED = "none declared"
EXCEPTIONS = "License exceptions"
UNDECLARED = "Licenses the installed metadata does not declare"
FIRST_PARTY = "First-party distributions"
# The project's own root package in the lockfile, and the group a release installs beside it.
PROJECT = "execbound"
RELEASE_GROUP = "showcase"


def load_lock(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def runtime(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every distribution a release installs, walked from the project through its extras.

    The walk follows each dependency's own `extra` list, so an optional dependency the
    project never asked for stays out: `psycopg[binary]` brings `psycopg-binary` because the
    project asks for that extra, and `mcp`'s unrequested extras bring nothing.
    """
    packages = {package["name"]: package for package in lock["package"]}
    root = packages[PROJECT]
    seeds = list(root.get("dependencies", []))
    seeds += root.get("dev-dependencies", {}).get(RELEASE_GROUP, [])
    found: dict[str, dict[str, Any]] = {}
    stack = [(dep["name"], tuple(dep.get("extra", [])), dep.get("marker")) for dep in seeds]
    while stack:
        name, extras, marker = stack.pop()
        package = packages.get(name)
        if package is None or name == PROJECT:
            continue
        entry = found.get(name)
        first = entry is None
        if entry is None:
            entry = found[name] = {
                "version": package.get("version", ""),
                "source": package.get("source", {}),
                "extras": set(),
                # The marker on the edge that reached it. An unmarked path wins, so a
                # distribution reached unconditionally is never reported as platform-only.
                "marker": marker,
            }
        elif marker is None:
            entry["marker"] = None
        new = set(extras) - entry["extras"]
        entry["extras"] |= set(extras)
        following = list(package.get("dependencies", [])) if first else []
        for extra in new:
            following += package.get("optional-dependencies", {}).get(extra, [])
        for dep in following:
            stack.append((dep["name"], tuple(dep.get("extra", [])), dep.get("marker")))
    for name, entry in found.items():
        entry["hash"] = lock_hash(packages[name])
    return found


def lock_hash(package: dict[str, Any]) -> str | None:
    """The lockfile's own digest for a distribution, where one describes it."""
    sdist = package.get("sdist") or {}
    wheels = package.get("wheels") or []
    chosen = sdist.get("hash") if sdist.get("hash") else None
    if chosen is None and len(wheels) == 1:
        chosen = wheels[0].get("hash")
    if isinstance(chosen, str) and chosen.startswith("sha256:"):
        return chosen.removeprefix("sha256:")
    return None


def declared(name: str) -> str | None:
    """The license a distribution's installed metadata declares, as an SPDX expression."""
    try:
        found = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return None
    expression = (found.get("License-Expression") or "").strip()
    if expression:
        return expression
    legacy = (found.get("License") or "").strip()
    if legacy in {"BSD", "PSF"}:
        return None
    if legacy and "\n" not in legacy and len(legacy) <= 80 and EXPRESSION.match(legacy):
        return legacy
    return None


def environment(names: list[str]) -> dict[str, str]:
    """Every name that is installed here, with the license its metadata declares."""
    return {name: found for name in names if (found := declared(name)) is not None}


def sections(document: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    current = ""
    for line in document.read_text(encoding="utf-8").splitlines():
        heading = SECTION.match(line)
        if heading:
            current = heading.group(1)
            found.setdefault(current, [])
        elif current:
            found[current].append(line)
    return found


def table(lines: list[str]) -> dict[str, tuple[str, str]]:
    """Distribution to (license, reason), from the document's one table."""
    rows: dict[str, tuple[str, str]] = {}
    for line in lines:
        row = ROW.match(line)
        if row:
            rows[row.group(1)] = (row.group(2).strip(), row.group(3).strip())
    return rows


def named(lines: list[str]) -> set[str]:
    """Every backticked name a section's bullets carry before their colon."""
    found: set[str] = set()
    for line in lines:
        if line.startswith("- "):
            found.update(NAME.findall(line.split(":", 1)[0]))
    return found


def allowed(expression: str) -> bool:
    """Whether an SPDX expression is inside the allowlist.

    An `OR` expression is allowed when any identifier is; anything else needs every
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
    resolved: dict[str, dict[str, Any]],
    installed: dict[str, str],
    document: dict[str, list[str]],
) -> list[str]:
    """One sentence for every runtime distribution the document does not account for."""
    listed = table(document.get(TABLE, []))
    excepted = named(document.get(EXCEPTIONS, []))
    undeclared = named(document.get(UNDECLARED, []))
    first_party = named(document.get(FIRST_PARTY, []))
    problems: list[str] = []
    for name in sorted(resolved):
        entry = resolved[name]
        ours = bool(entry["source"].keys() & {"editable", "directory", "virtual"})
        if name not in listed:
            problems.append(f"{name} is a runtime distribution and DEPENDENCIES.md omits it")
            continue
        recorded = listed[name][0]
        metadata_licence = installed.get(name)
        if metadata_licence is None:
            if ours:
                if name not in first_party:
                    problems.append(f"{name} is ours and is not named under '{FIRST_PARTY}'")
                continue
            if name not in undeclared:
                problems.append(
                    f"{name} declares no license here and is not named under '{UNDECLARED}'"
                )
                continue
        elif metadata_licence != recorded:
            problems.append(
                f"{name} declares {metadata_licence} and DEPENDENCIES.md records {recorded}"
            )
            continue
        if REFUSED.search(recorded):
            problems.append(f"{name} is {recorded}, which no exception admits")
        elif not allowed(recorded) and name not in excepted:
            problems.append(f"{name} is {recorded} and is not named under '{EXCEPTIONS}'")
    for stale in sorted((listed.keys() | excepted | undeclared | first_party) - resolved.keys()):
        problems.append(f"{stale} is in DEPENDENCIES.md and is not a runtime distribution")
    return problems


def bom(
    resolved: dict[str, dict[str, Any]], licences: dict[str, str], revision: str
) -> dict[str, Any]:
    components = []
    for name in sorted(resolved):
        entry = resolved[name]
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": entry["version"],
            "purl": f"pkg:pypi/{name}@{entry['version']}",
        }
        if entry["hash"]:
            component["hashes"] = [{"alg": "SHA-256", "content": entry["hash"]}]
        properties = []
        if entry["marker"]:
            properties.append({"name": "execbound:marker", "value": entry["marker"]})
        if entry["source"].keys() & {"editable", "directory", "virtual"}:
            properties.append({"name": "execbound:first-party", "value": "true"})
        if properties:
            component["properties"] = properties
        licence = licences.get(name)
        if licence and licence != NONE_DECLARED:
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
                "name": "execbound",
                "version": revision or "unknown",
            },
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--dependencies", type=Path, required=True, help="DEPENDENCIES.md")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", default="")
    args = parser.parse_args(argv)
    resolved = runtime(load_lock(args.lockfile))
    installed = environment(sorted(resolved))
    document = sections(args.dependencies)
    problems = findings(resolved, installed, document)
    listed = table(document.get(TABLE, []))
    licences = {name: installed.get(name) or listed.get(name, ("", ""))[0] for name in resolved}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(bom(resolved, licences, args.revision), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"{len(resolved)} runtime distributions written to {args.output}")
    for problem in problems:
        print(f"license: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
