# SPDX-License-Identifier: AGPL-3.0-only
"""Each `LICENSE` is a copyright line and an SPDX identifier over the canonical text, unchanged.

The recorded licence map (#122; #496) is applied by directory:
AGPL-3.0-only at the root, Apache-2.0 for what runs inside someone else's code or is copied
into their configuration, and CC BY 4.0 for documentation. The texts come from the SPDX
License List Data copies in `scripts/licence-texts/`, so a `LICENSE` cannot drift from SPDX
and the notices cannot drift from the `LICENSE` files. The package metadata and the wheel
check are held to the same map.
"""

import hashlib
import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEXTS = ROOT / "scripts" / "licence-texts"
COPYRIGHT = "Copyright 2026 ExecBound LLC"
SCOPE = "Directories that carry their own LICENSE file are licensed under that file instead."

LICENCES = {
    "LICENSE": "AGPL-3.0-only",
    "clients/python/LICENSE": "Apache-2.0",
    "examples/LICENSE": "Apache-2.0",
    "integrations/LICENSE": "Apache-2.0",
    "integrations/mde-producer/LICENSE": "Apache-2.0",
    "protocol/LICENSE": "Apache-2.0",
    "connectors/LICENSE": "Apache-2.0",
    "deploy/LICENSE": "Apache-2.0",
    "src/execbound/data/community/LICENSE": "Apache-2.0",
    "src/execbound/data/starters/LICENSE": "Apache-2.0",
    "src/execbound/surfaces/templates/recipes/LICENSE": "Apache-2.0",
    "docs/LICENSE": "CC-BY-4.0",
}

_spec = importlib.util.spec_from_file_location(
    "check_wheel_licences", ROOT / "scripts" / "check_wheel_licences.py"
)
assert _spec is not None and _spec.loader is not None
check_wheel_licences = importlib.util.module_from_spec(_spec)
sys.modules["check_wheel_licences"] = check_wheel_licences
_spec.loader.exec_module(check_wheel_licences)


@pytest.mark.parametrize(("path", "identifier"), sorted(LICENCES.items()))
def test_each_licence_file_is_its_header_over_the_canonical_text_unchanged(path, identifier):
    text = (ROOT / path).read_text(encoding="utf-8")
    header = f"{COPYRIGHT}\nSPDX-License-Identifier: {identifier}\n"
    if path == "LICENSE":
        header += f"{SCOPE}\n"
    assert text.startswith(header), f"{path} does not open with its copyright and identifier"
    body = text[len(header) :]
    assert body == "\n" + (TEXTS / f"{identifier}.txt").read_text(encoding="utf-8"), (
        f"{path} is not the SPDX text of {identifier} unchanged"
    )


def test_the_canonical_texts_are_the_ones_their_readme_records():
    """The table is the provenance: a text edited in place fails here, not in review."""
    recorded = dict(
        re.findall(
            r"^\| `([^`]+)` \| `([0-9a-f]{64})` \|$", (TEXTS / "README.md").read_text(), re.M
        )
    )
    present = {p.stem for p in TEXTS.glob("*.txt")}
    assert present == set(recorded), "every text needs a recorded digest and every digest a text"
    for identifier, digest in recorded.items():
        actual = hashlib.sha256((TEXTS / f"{identifier}.txt").read_bytes()).hexdigest()
        assert actual == digest, f"{identifier}.txt differs from the SPDX copy recorded"


def test_every_licence_the_map_uses_has_a_canonical_text():
    for identifier in set(LICENCES.values()):
        assert (TEXTS / f"{identifier}.txt").is_file(), identifier


def test_the_package_metadata_declares_the_map():
    server = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert server["license"] == "AGPL-3.0-only"
    assert server["license-files"] == ["LICENSE", "THIRD_PARTY_NOTICES.md"]
    client = tomllib.loads((ROOT / "clients" / "python" / "pyproject.toml").read_text())["project"]
    assert client["license"] == "Apache-2.0"
    assert client["license-files"] == ["LICENSE"]
    console = json.loads((ROOT / "console" / "package.json").read_text())
    assert console["license"] == "AGPL-3.0-only"
    for project in (server, client):
        assert not any(c.startswith("License ::") for c in project.get("classifiers", [])), (
            "PEP 639 forbids a licence classifier beside a licence expression"
        )


def test_the_wheel_check_expects_what_the_packages_declare():
    """Two statements of one fact: the check cannot come to expect something else."""
    server = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    client = tomllib.loads((ROOT / "clients" / "python" / "pyproject.toml").read_text())["project"]
    expected = check_wheel_licences.EXPECTED
    assert expected["execbound"][0] == server["license"]
    assert sorted(expected["execbound"][1]) == sorted(server["license-files"])
    assert expected["execbound_client"][0] == client["license"]
    assert sorted(expected["execbound_client"][1]) == sorted(client["license-files"])


def test_the_wheel_check_expects_every_licence_inside_the_server_package():
    """The Apache directories inside `src/execbound/` travel in the server's wheel as package
    data, beside the code that reads them, so the wheel check names each of them and no other."""
    inside = {path for path in LICENCES if path.startswith("src/execbound/")}
    # One licence is not committed under src/: the console build copies `integrations/LICENSE`
    # beside the Tines stories it carries (#678), so the wheel holds it to that file.
    built = {
        "execbound/surfaces/console_dist/stories/tines/LICENSE": ROOT / "integrations" / "LICENSE"
    }
    every = check_wheel_licences.PACKAGED["execbound"]
    packaged = {member: source for member, source in every.items() if member not in built}
    assert {member: source for member, source in every.items() if member in built} == built
    assert {f"src/{member}" for member in packaged} == inside
    assert all(source == ROOT / "src" / member for member, source in packaged.items())
