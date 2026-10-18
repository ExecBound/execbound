# SPDX-License-Identifier: AGPL-3.0-only
"""Refuse a branch whose migrations would fork the revision graph when the base merges in.

Every check here verifies a pull request at its own head, and branch currency is
deliberately not required, so nothing ever sees the base branch and the pull request
together. Two branches can each hold one valid head, number their migration from the same
parent, and produce two alembic heads the moment the second one merges — which
`alembic upgrade head` then refuses on every database, including the hosted one. This
check reads both sets of revisions without merging anything, so it costs seconds rather
than a second full verification, and it fails while the fork is still one file to rename.
"""

import argparse
import ast
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

VERSIONS = "migrations/versions"


def parents_of(value: object) -> frozenset[str]:
    """Read a `down_revision` in any form alembic accepts.

    The first revision declares None, an ordinary revision a string, and a revision written
    by `alembic merge` a tuple of the lines it joins. Every form reduces to a set of parents.
    """
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    try:
        return frozenset(str(item) for item in value if item is not None)
    except TypeError:
        return frozenset()


def read_revision(source: str) -> tuple[str, frozenset[str]] | None:
    """Return a migration's own revision and its parents, or None if it declares none.

    The module is parsed rather than imported: a migration imports alembic and sqlalchemy
    and runs at a database, and this check must stay a stdlib-only read of the files.
    """
    try:
        module = ast.parse(source)
    except SyntaxError:
        return None
    declared: dict[str, object] = {}
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in ("revision", "down_revision"):
                try:
                    declared[target.id] = ast.literal_eval(node.value)
                except ValueError:
                    return None
    revision = declared.get("revision")
    if not isinstance(revision, str):
        return None
    return revision, parents_of(declared.get("down_revision"))


def heads(graph: Mapping[str, frozenset[str]]) -> set[str]:
    """The revisions no other revision claims as a parent."""
    claimed = {parent for parents in graph.values() for parent in parents}
    return {revision for revision in graph if revision not in claimed}


def named(parents: frozenset[str]) -> str:
    return ", ".join(sorted(parents)) if parents else "none"


def report(
    base: Mapping[str, frozenset[str]],
    branch: Mapping[str, frozenset[str]],
    base_name: str = "the base branch",
) -> list[str]:
    """Return every problem in the merged revision graph; an empty list means it is linear."""
    problems = []
    for revision in sorted(set(base) & set(branch)):
        if base[revision] != branch[revision]:
            problems.append(
                f"{revision} declares parent {named(base[revision])} on {base_name} and "
                f"{named(branch[revision])} here. A merged migration's parent is frozen "
                "history and must not be rewritten."
            )
    union = {**base, **branch}
    if not union:
        return problems
    found = heads(union)
    if len(found) > 1:

        def side(revision: str) -> str:
            if revision in base and revision in branch:
                return "both"
            return base_name if revision in base else "this branch"

        listed = ", ".join(
            f"{revision} ({side(revision)}, parent {named(union[revision])})"
            for revision in sorted(found)
        )
        problems.append(
            f"Merging {base_name} would leave {len(found)} alembic heads: {listed}. "
            "Re-parent this branch's migration onto the base head and renumber it."
        )
    elif not found:
        # Unreachable through ordinary use, but a graph with no head is a cycle, and a check
        # that stayed quiet about it would be reporting success for an unusable database.
        problems.append(
            "The merged revision graph has no head, so it contains a cycle: "
            f"{', '.join(sorted(union))}."
        )
    return problems


def git(*arguments: str) -> str:
    result = subprocess.run(["git", *arguments], capture_output=True, text=True, check=True)
    return result.stdout


def collect_ref(ref: str) -> dict[str, frozenset[str]]:
    """Read every migration at a git ref without checking it out or merging it."""
    graph: dict[str, frozenset[str]] = {}
    for path in git("ls-tree", "-r", "--name-only", ref, "--", VERSIONS).splitlines():
        if not path.endswith(".py") or path.endswith("__init__.py"):
            continue
        read = read_revision(git("show", f"{ref}:{path}"))
        if read is not None:
            graph[read[0]] = read[1]
    return graph


def collect_tree(root: Path) -> dict[str, frozenset[str]]:
    graph: dict[str, frozenset[str]] = {}
    for path in sorted((root / VERSIONS).glob("*.py")):
        if path.name == "__init__.py":
            continue
        read = read_revision(path.read_text(encoding="utf-8"))
        if read is not None:
            graph[read[0]] = read[1]
    return graph


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that a merge would leave one head")
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--root", type=Path, default=Path())
    arguments = parser.parse_args(argv)
    try:
        base = collect_ref(arguments.base)
    except subprocess.CalledProcessError:
        # Refusing here is the point: a check that passes when it could not read the base
        # would report success for exactly the misconfiguration it exists to catch.
        print(
            f"Cannot read {arguments.base}. Fetch it before running this check.",
            file=sys.stderr,
        )
        return 2
    problems = report(base, collect_tree(arguments.root), arguments.base)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"One alembic head after merging {arguments.base}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
