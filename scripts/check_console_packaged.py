# SPDX-License-Identifier: AGPL-3.0-only
"""Refuse a server distribution that does not carry the console the workspace built.

    uv run python scripts/check_console_packaged.py dist/execbound-*.whl dist/execbound-*.tar.gz

`pnpm build` writes the console into `src/execbound/surfaces/console_dist/`, which git ignores,
and hatch leaves ignored files out of a distribution unless its `artifacts` line names them.
The wheel's line alone was not enough: a plain `uv build` makes the sdist first and the wheel
from the sdist, so until the sdist named it too both came out with no console, and the build
said nothing. The server then starts and every console page says the package has none.

Each distribution given must carry that directory exactly as the workspace holds it: every
file, byte for byte, and nothing else. The workspace build is the reference, so run this after
`pnpm build` and `uv build` in the same checkout; with no build in the workspace there is
nothing to compare against, and that is refused rather than passed.
"""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "src" / "execbound" / "surfaces" / "console_dist"
# Where the build sits inside each kind of distribution, after its own top-level directory.
WHEEL_PREFIX = "execbound/surfaces/console_dist/"
SDIST_PREFIX = "src/execbound/surfaces/console_dist/"


def reference(build: Path = BUILD) -> dict[str, bytes]:
    """The workspace build, keyed by path under `console_dist/`."""
    if not (build / "index.html").is_file():
        return {}
    return {
        path.relative_to(build).as_posix(): path.read_bytes()
        for path in sorted(build.rglob("*"))
        if path.is_file()
    }


def packaged(distribution: Path) -> dict[str, bytes]:
    """The console files one wheel or sdist carries, keyed the same way."""
    found: dict[str, bytes] = {}
    if distribution.name.endswith(".whl"):
        with zipfile.ZipFile(distribution) as archive:
            for name in archive.namelist():
                if name.startswith(WHEEL_PREFIX) and not name.endswith("/"):
                    found[name[len(WHEEL_PREFIX) :]] = archive.read(name)
        return found
    with tarfile.open(distribution, "r:gz") as archive:
        for member in archive.getmembers():
            # An sdist holds one top-level directory, `<name>-<version>/`.
            inner = member.name.split("/", 1)[1] if "/" in member.name else ""
            if member.isfile() and inner.startswith(SDIST_PREFIX):
                handle = archive.extractfile(member)
                assert handle is not None
                found[inner[len(SDIST_PREFIX) :]] = handle.read()
    return found


def problems(distribution: Path, expected: dict[str, bytes]) -> list[str]:
    """Every way one distribution's console differs from the workspace build."""
    name = distribution.name
    if not (name.endswith(".whl") or name.endswith(".tar.gz")):
        return [f"{name}: not a wheel or an sdist"]
    carried = packaged(distribution)
    if not carried:
        return [f"{name}: carries no console at all"]
    found = [f"{name}: {path} is missing" for path in sorted(expected.keys() - carried.keys())]
    found += [f"{name}: {path} is not in the build" for path in sorted(carried.keys() - expected)]
    found += [
        f"{name}: {path} differs from the build"
        for path in sorted(expected.keys() & carried.keys())
        if expected[path] != carried[path]
    ]
    return found


def main(argv: list[str] | None = None, build: Path = BUILD) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("distributions", nargs="+", type=Path, help="built .whl and .tar.gz files")
    args = parser.parse_args(argv)
    expected = reference(build)
    if not expected:
        print(
            f"check_console_packaged: no console build at {build}; run `pnpm build` first",
            file=sys.stderr,
        )
        return 2
    failures = [p for distribution in args.distributions for p in problems(distribution, expected)]
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(
        f"{len(args.distributions)} distribution(s) carry the console build ({len(expected)} files)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
