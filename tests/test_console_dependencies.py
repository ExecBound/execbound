# SPDX-License-Identifier: AGPL-3.0-only
"""`console/DEPENDENCIES.md` is the reviewed list; `package.json` and the pnpm settings match it.

A dependency is a supply-chain decision (#333). This test reads the manifest, the pnpm settings
and the document with the standard library only, so it runs in the Python suite without Node,
and fails when any of the three drifts from the other two.
"""

import json
import re
from pathlib import Path

CONSOLE = Path(__file__).resolve().parents[1] / "console"
DOCUMENT = CONSOLE / "DEPENDENCIES.md"
MANIFEST = CONSOLE / "package.json"
SETTINGS = CONSOLE / "pnpm-workspace.yaml"

ROW = re.compile(r"^\| `([^`]+)` \| ([^|]+?) \|")
SECTION = re.compile(r"^## (.+)$")


def sections() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    current = ""
    for line in DOCUMENT.read_text(encoding="utf-8").splitlines():
        heading = SECTION.match(line)
        if heading:
            current = heading.group(1)
            found[current] = []
        elif current:
            found[current].append(line)
    return found


def listed(lines: list[str]) -> dict[str, str]:
    rows = {}
    for line in lines:
        row = ROW.match(line)
        if row and row.group(1) != "Package":
            rows[row.group(1)] = row.group(2).strip()
    return rows


def allowed_builds() -> set[str]:
    """The packages `allowBuilds` names, read from the YAML mapping without a YAML parser."""
    names: set[str] = set()
    inside = False
    for line in SETTINGS.read_text(encoding="utf-8").splitlines():
        if line.startswith("allowBuilds:"):
            inside = line.rstrip() in ("allowBuilds:",)
            continue
        if inside:
            if not line.startswith(" ") or not line.strip():
                inside = False
                continue
            names.add(line.strip().split(":")[0].strip("'\""))
    return names


def test_the_document_and_the_manifest_list_the_same_packages_at_the_same_versions():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    parts = sections()
    assert listed(parts["Runtime"]) == manifest["dependencies"]
    assert listed(parts["Development"]) == manifest["devDependencies"]


def test_every_version_is_exact():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    exact = re.compile(r"^\d+\.\d+\.\d+$")
    for group in ("dependencies", "devDependencies"):
        for name, version in manifest[group].items():
            assert exact.match(version), (name, version)
    assert exact.match(manifest["engines"]["node"]) and exact.match(manifest["engines"]["pnpm"])
    assert manifest["packageManager"].startswith("pnpm@" + manifest["engines"]["pnpm"] + "+sha512.")


def test_an_install_on_any_other_node_is_refused():
    """`engines` names one Node, and pnpm refuses any other only with `engineStrict`. pnpm 11
    reads that setting from the workspace file and ignores it in `.npmrc`, where it once was:
    an install on Node 22 there warned and carried on (probed with pnpm 11.26.0, September 30,
    2026). With the setting here, the same install stops."""
    assert re.search(r"^engineStrict: true$", SETTINGS.read_text(encoding="utf-8"), re.MULTILINE)
    assert not (CONSOLE / ".npmrc").exists()


def test_install_scripts_are_refused_unless_recorded_here():
    settings = SETTINGS.read_text(encoding="utf-8")
    assert "strictDepBuilds: true" in settings
    assert "minimumReleaseAge: 10080" in settings
    recorded = {
        match.group(1)
        for line in sections()["Install scripts"]
        if line.startswith("- ")
        for match in [re.match(r"^- `([^`]+)`", line)]
        if match
    }
    assert allowed_builds() == recorded


def test_every_reason_is_stated():
    for section in ("Runtime", "Development"):
        for line in sections()[section]:
            row = ROW.match(line)
            if row and row.group(1) != "Package":
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                assert len(cells[2]) >= 12, (row.group(1), "needs a reason")
