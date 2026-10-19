# SPDX-License-Identifier: AGPL-3.0-only
"""Every file's license, and the one line in it that names that license (#496).

    python3 scripts/licence_headers.py            # check every tracked file
    python3 scripts/licence_headers.py --write    # add or correct each missing or wrong line

A file takes the license of the longest prefix of its path in `LICENCE_MAP`, unless
`FILE_LICENCES` names the file itself. A file under `export/public/` is a replacement the
export copies to the rest of its path, so it answers for that destination.

A file whose type has a comment syntax carries one `SPDX-License-Identifier` line in that
syntax: on its first line, or on its second after a `#!` line or an `<?xml` declaration, which
must stay first. A Jinja template's line is always its first. Markdown, JSON, CSV, lockfiles,
binary files and empty files take the map without a line, and so do the paths `EXEMPT`
names. Of the exempt files, only a license file (`LICENSE`, `LICENSE.txt`) carries a line,
which names the license the map gives; any other exempt file carries none. A file that takes a
line may not open with a byte-order mark, and a symbolic link is never followed, in any part of
a file's path: git records the link, and its target is checked under its own path.

Both modes read the files git tracks, or, where the root has no `.git` or git tracks nothing
there yet, every file a walk finds outside what the root's `.gitignore` keeps out of a commit.
After merging `main`, a branch runs `--write` once and commits what it changed;
`tests/test_licence_headers.py` names any file still wrong. The script is public, standard
library only, and runs under Python 3.12.
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
TAG = "SPDX-License-Identifier"
PROPRIETARY = "LicenseRef-ExecBound-Proprietary"
EXPORT_PREFIX = "export/public/"

# (path prefix, SPDX identifier). The longest prefix a path starts with wins; "" is the root.
# Each prefix with a canonical license text holds a `LICENSE` naming the same identifier. The
# fonts' license file is `LICENSE.txt`, and the proprietary directories have none. The public
# website, `site/`, is served as it is committed and never distributed, so it is proprietary
# and takes the map without a line (`EXEMPT`); its fonts keep their own license.
LICENCE_MAP: tuple[tuple[str, str], ...] = (
    ("", "AGPL-3.0-only"),
    ("clients/python/", "Apache-2.0"),
    ("examples/", "Apache-2.0"),
    ("integrations/", "Apache-2.0"),
    ("integrations/mde-producer/", "Apache-2.0"),
    ("protocol/", "Apache-2.0"),
    ("connectors/", "Apache-2.0"),
    ("deploy/", "Apache-2.0"),
    ("src/execbound/data/community/", "Apache-2.0"),
    ("src/execbound/data/starters/", "Apache-2.0"),
    ("src/execbound/surfaces/templates/recipes/", "Apache-2.0"),
    ("docs/", "CC-BY-4.0"),
    ("console/public/fonts/", "OFL-1.1"),
    ("site/fonts/", "OFL-1.1"),
    ("site/", PROPRIETARY),
    ("src/execbound/hosted/", PROPRIETARY),
    ("console/src/hosted/", PROPRIETARY),
    ("tests/hosted/", PROPRIETARY),
)

# Exact paths whose license is not their directory's. The Contributor Covenant is its authors'
# text under CC BY 4.0 wherever it sits.
FILE_LICENCES: dict[str, str] = {"CODE_OF_CONDUCT.md": "CC-BY-4.0"}

# Paths that take the map without a line, as `fnmatch` patterns, where `*` also matches `/`.
EXEMPT: tuple[str, ...] = (
    # Applied migrations, 0001 to 0067, are never edited, not even to add a comment. A new
    # revision takes its line from the Alembic template or from `--write`.
    "migrations/versions/00[0-5][0-9]_*.py",
    "migrations/versions/006[0-7]_*.py",
    # Held byte for byte: the fixtures, the license texts their recorded digests pin, and
    # every license file, which opens with its own identifier.
    "tests/fixtures/*",
    "scripts/licence-texts/*",
    "LICENSE",
    "*/LICENSE",
    "LICENSE.txt",
    "*/LICENSE.txt",
    # The public website is served as it is committed, so no line reaches its pages. The
    # console's favicon is the website's byte for byte, so it goes without one too.
    "site/*",
    "console/public/favicon.svg",
    # Rewritten whole by a tool that would drop the line.
    "uv.lock",
    "console/pnpm-lock.yaml",
    "docs-site/pnpm-lock.yaml",
    "tests/sdk-examples.txt",
    "tests/mcp-legacy.txt",
    "src/execbound/hosted/data/disposable_domains.txt",
)


@dataclass(frozen=True)
class Syntax:
    """How a file type writes a one-line comment: what opens it and what closes it."""

    start: str
    end: str


HASH = Syntax("# ", "")
SLASHES = Syntax("// ", "")
BLOCK = Syntax("/* ", " */")
MARKUP = Syntax("<!-- ", " -->")
# Jinja's comment with whitespace control on both sides: the comment and the line break after
# it render as nothing, so every page and recipe renders byte for byte as it did without it.
JINJA = Syntax("{#- ", " -#}")

# Directories whose every file is a Jinja template, whatever its extension.
TEMPLATES = ("src/execbound/surfaces/templates/", "src/execbound/hosted/templates/")

# By file name, looked up before the suffix. None: the file takes the map without a line.
NAMES: dict[str, Syntax | None] = {
    "Dockerfile": HASH,
    "CODEOWNERS": HASH,
    ".gitignore": HASH,
    ".gitleaksignore": HASH,
    ".gitattributes": HASH,
    ".dockerignore": HASH,
    ".npmrc": HASH,
    ".env.example": HASH,
    ".python-version": HASH,
    # Alembic's template for a new revision. Mako passes a `#` line through (`##` is its own
    # comment), so every new migration opens with the line.
    "script.py.mako": HASH,
    "py.typed": None,
}
SUFFIXES: dict[str, Syntax | None] = {
    ".py": HASH,
    ".sh": HASH,
    ".yaml": HASH,
    ".yml": HASH,
    ".toml": HASH,
    ".ini": HASH,
    ".in": HASH,
    ".txt": HASH,
    ".ts": SLASHES,
    ".tsx": SLASHES,
    ".js": SLASHES,
    ".mjs": SLASHES,
    ".css": BLOCK,
    ".html": MARKUP,
    ".svg": MARKUP,
    ".xml": MARKUP,
    ".md": None,
    ".json": None,
    ".csv": None,
    ".lock": None,
    ".woff2": None,
    ".ico": None,
    ".png": None,
    ".webp": None,
}

# A line holding the tag after nothing but blanks and comment marks, in any syntax above, or
# bare, as a license file writes it. A line of code that quotes the tag is not one.
SPDX_LINE = re.compile(r"^[\s#/*!<{-]*" + re.escape(TAG) + r"\b")
IDENTIFIER = re.compile(re.escape(TAG) + r":\s*([A-Za-z0-9.+-]*[A-Za-z0-9+])")
# A line written before a byte-order mark would leave the mark inside the file.
BOM = "\ufeff"
# The exempt files that open with their own line: every license file names its license.
LICENCE_FILES = frozenset({"LICENSE", "LICENSE.txt"})


class UnknownType(ValueError):
    """A file whose type this script has no decision for."""


def _destination(path: str) -> str:
    """The path `path` answers for: a replacement answers for the path the export gives it."""
    return path[len(EXPORT_PREFIX) :] if path.startswith(EXPORT_PREFIX) else path


def _template(path: str) -> bool:
    """Whether `path` is a Jinja template: every file under a templates directory is one."""
    return _destination(path).startswith(TEMPLATES)


def licence_for(path: str) -> str:
    """The SPDX identifier of `path`, a POSIX path relative to the repository's root."""
    path = _destination(path)
    if path in FILE_LICENCES:
        return FILE_LICENCES[path]
    matches = [entry for entry in LICENCE_MAP if path.startswith(entry[0])]
    return max(matches, key=lambda entry: len(entry[0]))[1]


def is_exempt(path: str) -> bool:
    """Whether `path` is one `EXEMPT` names, so `write` never changes it."""
    path = _destination(path)
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in EXEMPT)


def syntax_for(path: str) -> Syntax | None:
    """The comment syntax `path`'s line is written in, or None where the file takes the map
    without a line: Markdown, JSON, CSV, binaries, lockfiles and every path in `EXEMPT`. An
    empty file carries no line either, which `problems` and `write` read from its content.
    A type with no decision here raises `UnknownType`, so a new type is decided once."""
    if is_exempt(path):
        return None
    if _template(path):
        return JINJA
    path = _destination(path)
    name = PurePosixPath(path).name
    if name in NAMES:
        return NAMES[name]
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in SUFFIXES:
        return SUFFIXES[suffix]
    raise UnknownType(
        f"no comment syntax is recorded for {name!r}: add its name or suffix to NAMES or "
        "SUFFIXES in scripts/licence_headers.py, with None if it takes the map without a line"
    )


def header_line(path: str) -> str | None:
    """The exact line `path` carries, or None where `syntax_for` is None."""
    syntax = syntax_for(path)
    if syntax is None:
        return None
    return f"{syntax.start}{TAG}: {licence_for(path)}{syntax.end}"


def expected_position(lines: list[str], path: str | None = None) -> int:
    """The index of the line: 0, or 1 after a `#!` line or an `<?xml` declaration.

    A Jinja template's line is always first, whatever its first line holds: `{#-` strips the
    line break before it, so a line put second would join the first line to the third."""
    if path is not None and _template(path):
        return 0
    return 1 if lines and lines[0].startswith(("#!", "<?xml")) else 0


def _ignore_rules(root: Path) -> list[tuple[bool, bool, bool, str]]:
    """The root `.gitignore`'s patterns, as (negated, directories only, anchored, pattern)."""
    try:
        text = (root / ".gitignore").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        line = line.removeprefix("!")
        directory = line.endswith("/")
        line = line.rstrip("/")
        anchored = "/" in line
        rules.append((negated, directory, anchored, line.lstrip("/")))
    return rules


def _ignored(path: str, is_directory: bool, rules: list[tuple[bool, bool, bool, str]]) -> bool:
    ignored = False
    for negated, directory, anchored, pattern in rules:
        if directory and not is_directory:
            continue
        if fnmatch.fnmatchcase(path if anchored else path.rsplit("/", 1)[-1], pattern):
            ignored = not negated
    return ignored


def _walk(root: Path) -> list[str]:
    rules = _ignore_rules(root)
    found: list[str] = []
    for directory, subdirectories, files in os.walk(root):
        here = Path(directory).relative_to(root).as_posix()
        prefix = "" if here == "." else f"{here}/"
        subdirectories[:] = [
            name
            for name in subdirectories
            if name != ".git" and not _ignored(prefix + name, True, rules)
        ]
        found += [prefix + name for name in files if not _ignored(prefix + name, False, rules)]
    return sorted(found)


def tracked(root: Path) -> list[str]:
    """The files under `root`, as sorted POSIX paths relative to it: what `git ls-files` lists,
    or a walk where `root` has no `.git` or git lists nothing there yet."""
    if (root / ".git").exists():
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
        ).stdout
        paths = sorted(path for path in listed.decode("utf-8").split("\0") if path)
        if paths:
            return paths
    return _walk(root)


def _text(file: Path) -> str | None:
    try:
        return file.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return None


def problems(root: Path, paths: Iterable[str]) -> list[str]:
    """Every way the files at `paths` under `root` differ from the map: a missing or wrong
    line, a line on a file that takes the map without one, and a second line anywhere."""
    found: list[str] = []
    root = root.resolve()
    for path in paths:
        file = root / path
        # A file is read at its own path only. A link, as the file itself or as any directory
        # above it, reaches a file the map answers for under another path, perhaps outside the
        # tree. The root is resolved above, so only a link inside the tree makes the paths differ.
        if file.resolve() != file or not file.is_file():
            continue
        try:
            want = header_line(path)
        except UnknownType as unknown:
            found.append(f"{path}: {unknown}")
            continue
        text = _text(file)
        if text is None:
            if want is not None:
                found.append(f"{path}: not UTF-8 text, so its line cannot be read")
            continue
        if text.startswith(BOM):
            if want is not None:
                found.append(f"{path}: starts with a byte-order mark; remove it")
            continue
        if not text:
            continue
        lines = text.split("\n")
        if want is None:
            found += _unlined(path, lines)
            continue
        position = expected_position(lines, path)
        at = lines[position].rstrip("\r") if position < len(lines) else ""
        if at != want:
            what = "a wrong" if SPDX_LINE.match(at) else "no"
            found.append(f"{path}:{position + 1}: {what} {TAG} line; it must read {want!r}")
        for number, line in enumerate(lines, start=1):
            if number != position + 1 and SPDX_LINE.match(line):
                found.append(
                    f"{path}:{number}: a second {TAG} line; the file's one line is its "
                    f"line {position + 1}"
                )
    return found


def _unlined(path: str, lines: list[str]) -> list[str]:
    """A file that takes the map. A license file may open with a line naming its license; any
    other exempt file carries no line anywhere, and a file of a type that takes the map must
    not open with one."""
    found: list[str] = []
    if not is_exempt(path):
        for number, line in enumerate(lines[:2], start=1):
            if SPDX_LINE.match(line):
                found.append(f"{path}:{number}: this type takes the map without a line; remove it")
        return found
    if PurePosixPath(path).name not in LICENCE_FILES:
        for number, line in enumerate(lines, start=1):
            if SPDX_LINE.match(line):
                found.append(
                    f"{path}:{number}: this file is exempt and takes no {TAG} line; remove it"
                )
        return found
    licence = licence_for(path)
    for number, line in enumerate(lines[:2], start=1):
        if not SPDX_LINE.match(line):
            continue
        named = IDENTIFIER.search(line)
        if named is None or named.group(1) != licence:
            found.append(f"{path}:{number}: the line must name {licence}, as the map does")
    return found


def write(root: Path, paths: Iterable[str]) -> list[str]:
    """Add the line where it is missing and correct it where it is wrong, in every file at
    `paths` that carries one. Never touches an exempt file, a file reached through a symbolic
    link or a file that opens with a byte-order mark, and never removes a second line, which
    `problems` still reports. Returns the paths it changed."""
    changed: list[str] = []
    root = root.resolve()
    for path in paths:
        file = root / path
        # As in `problems`: a link anywhere in the path would write where it points. Git's index
        # can name `pkg/a.py` while `pkg` is a link on disk, so a tracked path is no proof.
        if file.resolve() != file or not file.is_file() or is_exempt(path):
            continue
        try:
            want = header_line(path)
        except UnknownType:
            continue
        text = _text(file) if want is not None else None
        if not text or want is None or text.startswith(BOM):
            continue
        lines = text.split("\n")
        position = expected_position(lines, path)
        ending = "\r" if lines[0].endswith("\r") else ""
        if position < len(lines) and SPDX_LINE.match(lines[position]):
            lines[position] = want + ending
        else:
            lines.insert(position, want + ending)
        rewritten = "\n".join(lines)
        if rewritten != text:
            file.write_bytes(rewritten.encode("utf-8"))
            changed.append(path)
    return changed


def main(argv: list[str] | None = None) -> int:
    """`--check` (the default) or `--write`: 0 when every line is right, 1 naming each
    problem, and 2 for a usage error, a git that cannot list the files, or a file that
    cannot be read or written."""
    parser = argparse.ArgumentParser(
        prog="licence_headers.py", description=(__doc__ or "").split("\n\n")[0]
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true", help="name every file whose line is wrong (the default)"
    )
    mode.add_argument(
        "--write", action="store_true", help="add or correct each missing or wrong line, then check"
    )
    parser.add_argument(
        "--root", type=Path, default=ROOT, help="the tree to read (default: this repository)"
    )
    parser.add_argument(
        "paths", nargs="*", help="files relative to the root (default: every tracked file)"
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 2
    root = args.root.resolve()
    if not root.is_dir():
        print(f"licence_headers: {args.root} is not a directory", file=sys.stderr)
        return 2
    paths: list[str] = []
    for given in args.paths:
        # A path is read at its own path, so it must resolve to itself: one through `..` or
        # a symbolic link would take the license of the path as written, not of what it reaches.
        relative = PurePosixPath(Path(given).as_posix())
        file = root / relative
        if relative.is_absolute() or file.resolve() != file or not file.is_file():
            print(
                f"licence_headers: {given} is not a file under {root} at its own path",
                file=sys.stderr,
            )
            return 2
        paths.append(relative.as_posix())
    if not args.paths:
        try:
            paths = tracked(root)
        except (OSError, subprocess.CalledProcessError) as failed:
            said = failed.stderr if isinstance(failed, subprocess.CalledProcessError) else b""
            why = (said or b"").decode("utf-8", "replace").strip().splitlines()
            reason = why[0] if why else str(failed)
            print(
                f"licence_headers: git could not list the files under {root}: {reason}",
                file=sys.stderr,
            )
            return 2
    try:
        written = len(write(root, paths)) if args.write else 0
        found = problems(root, paths)
    except OSError as error:
        print(f"licence_headers: {error}", file=sys.stderr)
        return 2
    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        print(
            f"licence_headers: {len(found)} problem(s) in {len(paths)} files. `--write` adds "
            "or corrects a missing or wrong line; every other problem is fixed by hand.",
            file=sys.stderr,
        )
        return 1
    wrote = f", {written} written" if args.write else ""
    print(f"licence_headers: {len(paths)} files read{wrote}; every line is right")
    return 0


if __name__ == "__main__":
    sys.exit(main())
