# SPDX-License-Identifier: AGPL-3.0-only
"""Refuse a built wheel that does not carry its license.

    uv run python scripts/check_wheel_licences.py dist/*.whl dist/client/*.whl \
        dist/protocol/*.whl dist/connectors/*.whl

PEP 639 puts a distribution's license files under `<name>.dist-info/licenses/` and its SPDX
expression in the `License-Expression` field. Each wheel this repository builds must carry
the `LICENSE` its directory holds, byte for byte, and declare the expression its
`pyproject.toml` does. The server's wheel also carries `THIRD_PARTY_NOTICES.md`, because it
bundles the built console and the console bundles third-party code (#122; #496). A wheel this
file does not know is refused rather than passed, so a new distribution has to be given its
license here before it can ship.

The server's wheel also carries, as package data, the `LICENSE` of each Apache-2.0 directory
inside the AGPL package: the install bundle, the starter policy packs, the MCP recipes and the
Tines stories. The server reads those directories from where they are, so each license has to
travel beside them. The Tines stories are copied into the console build from `integrations/`,
so their license's repository copy is `integrations/LICENSE`.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Wheel name, as the file name spells it, to (expression, {license file: repository copy}).
EXPECTED: dict[str, tuple[str, dict[str, Path]]] = {
    "execbound": (
        "AGPL-3.0-only",
        {
            "LICENSE": ROOT / "LICENSE",
            "THIRD_PARTY_NOTICES.md": ROOT / "THIRD_PARTY_NOTICES.md",
        },
    ),
    "execbound_client": ("Apache-2.0", {"LICENSE": ROOT / "clients" / "python" / "LICENSE"}),
    "execbound_protocol": ("Apache-2.0", {"LICENSE": ROOT / "protocol" / "LICENSE"}),
    "execbound_connectors": ("Apache-2.0", {"LICENSE": ROOT / "connectors" / "LICENSE"}),
}

# Wheel name to {archive member: repository copy}: the licenses a wheel carries beside the
# package data they cover, rather than under `.dist-info/licenses/`.
PACKAGED: dict[str, dict[str, Path]] = {
    "execbound": {
        **{
            member: ROOT / "src" / member
            for member in (
                "execbound/data/community/LICENSE",
                "execbound/data/starters/LICENSE",
                "execbound/surfaces/templates/recipes/LICENSE",
            )
        },
        # The console build copies the committed Tines stories and this license beside them.
        "execbound/surfaces/console_dist/stories/tines/LICENSE": ROOT / "integrations" / "LICENSE",
    },
}


def _shown(source: Path) -> Path:
    return source.relative_to(ROOT) if source.is_relative_to(ROOT) else source


def problems(
    wheel: Path,
    expected: dict[str, tuple[str, dict[str, Path]]] = EXPECTED,
    packaged: dict[str, dict[str, Path]] = PACKAGED,
) -> list[str]:
    """Every way one wheel fails to carry its licenses; empty when it carries them."""
    name = wheel.name.split("-", 1)[0]
    if name not in expected:
        return [f"{wheel.name}: no license is recorded for the distribution {name!r}"]
    expression, files = expected[name]
    found: list[str] = []
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        info = [n for n in names if n.count("/") == 1 and n.split("/")[0].endswith(".dist-info")]
        dist_info = {n.split("/")[0] for n in info}
        if len(dist_info) != 1:
            return [f"{wheel.name}: expected one .dist-info directory, found {sorted(dist_info)}"]
        (directory,) = dist_info
        fields = archive.read(f"{directory}/METADATA").decode("utf-8").split("\n\n", 1)[0]
        declared = [
            line.split(":", 1)[1].strip()
            for line in fields.splitlines()
            if line.startswith("License-Expression:")
        ]
        if declared != [expression]:
            found.append(
                f"{wheel.name}: License-Expression is {declared or 'absent'}, not {expression}"
            )
        members = {f"{directory}/licenses/{file}": source for file, source in files.items()}
        for member, source in (members | packaged.get(name, {})).items():
            if member not in names:
                found.append(f"{wheel.name}: {member} is missing")
            elif archive.read(member) != source.read_bytes():
                found.append(f"{wheel.name}: {member} differs from {_shown(source)}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("wheels", nargs="+", type=Path, help="built .whl files")
    args = parser.parse_args(argv)
    wheels = [w for w in args.wheels if w.suffix == ".whl"]
    if not wheels:
        print("check_wheel_licences: no wheel given", file=sys.stderr)
        return 2
    failures = [p for wheel in wheels for p in problems(wheel)]
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(f"{len(wheels)} wheel(s) carry their license")
    return 0


if __name__ == "__main__":
    sys.exit(main())
