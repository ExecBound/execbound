# SPDX-License-Identifier: AGPL-3.0-only
"""The npm SBOM reads the lockfile itself, and the licence allowlist holds the tree to it."""

import json

from console_sbom_fixtures import LOCKFILE, ROOT, load_script

sbom = load_script()

# The versions the console pins, read rather than repeated, so a dependency bump changes the
# manifest, the lockfile and console/DEPENDENCIES.md and never this test.
PINNED = json.loads((ROOT / "console" / "package.json").read_text(encoding="utf-8"))["dependencies"]


def test_the_lockfile_lists_every_package_with_its_integrity():
    resolved = sbom.packages(LOCKFILE)
    by_name = {(p["name"], p["version"]): p for p in resolved}
    react = by_name[("react", PINNED["react"])]
    assert react["algorithm"] == "sha512" and len(react["digest"]) == 128
    assert ("@tanstack/react-router", PINNED["@tanstack/react-router"]) in by_name
    assert all("digest" in p for p in resolved), [p for p in resolved if "digest" not in p][:3]
    assert len(resolved) > 100
    platform = [p["name"] for p in resolved if p.get("platform") == "true"]
    assert "@tailwindcss/oxide-darwin-arm64" in platform and "react" not in platform


def test_the_allowlist_reads_identifiers_and_expressions():
    assert sbom.allowed("MIT") and sbom.allowed("Apache-2.0") and sbom.allowed("0BSD")
    assert sbom.allowed("MIT-0") and sbom.allowed("Unlicense") and sbom.allowed("CC0-1.0")
    assert not sbom.allowed("BlueOak-1.0.0") and not sbom.allowed("CC-BY-4.0")
    assert sbom.allowed("(MIT OR Apache-2.0)") and sbom.allowed("MPL-2.0 OR MIT")
    assert not sbom.allowed("MPL-2.0") and not sbom.allowed("(MIT AND LGPL-3.0)")
    assert not sbom.allowed("") and not sbom.allowed("UNLICENSED")


def test_a_production_package_needs_an_allowed_licence_and_a_development_one_an_exception():
    resolved = [
        {"name": "react", "version": "19.3.0"},
        {"name": "some-tool", "version": "1.0.0"},
        {"name": "some-tool-linux-x64", "version": "1.0.0"},
        {"name": "other-tool", "version": "2.0.0"},
        {"name": "silent", "version": "3.0.0"},
        {"name": "elsewhere-darwin-arm64", "version": "3.0.0", "platform": "true"},
    ]
    known = {
        ("react", "19.3.0"): "MPL-2.0",
        ("some-tool", "1.0.0"): "MPL-2.0",
        ("some-tool-linux-x64", "1.0.0"): "MPL-2.0",
        ("other-tool", "2.0.0"): "MPL-2.0",
    }
    problems = sbom.findings(resolved, known, {"react"}, {"some-tool", "some-tool-*"})
    assert problems == [
        "react@19.3.0 ships to the browser under MPL-2.0",
        "other-tool@2.0.0 is MPL-2.0 and is not named in DEPENDENCIES.md's exceptions",
        "silent@3.0.0 declares no licence the listing knows",
    ]


def test_the_document_is_cyclonedx_with_hashes_and_licences(tmp_path):
    resolved = [{"name": "react", "version": "19.3.0", "algorithm": "sha512", "digest": "ab" * 64}]
    exceptions = tmp_path / "DEPENDENCIES.md"
    exceptions.write_text(
        "## Licence exceptions\n\n- `lightningcss` and `lightningcss-*`: MPL-2.0.\n"
        "- `lru-cache`: x.\n",
        encoding="utf-8",
    )
    assert sbom.exceptions(exceptions) == {"lightningcss", "lightningcss-*", "lru-cache"}
    document = sbom.bom(resolved, {("react", "19.3.0"): "MIT"}, "abc1234")
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
    [component] = document["components"]
    assert component["purl"] == "pkg:npm/react@19.3.0"
    assert component["hashes"] == [{"alg": "SHA-512", "content": "ab" * 64}]
    assert component["licenses"] == [{"license": {"id": "MIT"}}]
    assert document["metadata"]["component"]["version"] == "abc1234"
    listing = tmp_path / "licenses.json"
    listing.write_text(
        json.dumps({"MIT": [{"name": "react", "versions": ["19.3.0"]}]}), encoding="utf-8"
    )
    assert sbom.licences(listing) == {("react", "19.3.0"): "MIT"}
