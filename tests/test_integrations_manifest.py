# SPDX-License-Identifier: AGPL-3.0-only
"""docs/INTEGRATIONS.md is rendered from integrations/manifest.json. Every row's evidence
claim is checked here against what the exported tree holds, so a row cannot claim more than its
tests actually support (#250); the page's own content (its links resolve, it names no
commercial word) is checked here too, since the page is exported, and so is the trial record a
row names, which the trust center publishes. The landscape heading a row's anchor names, and a
recipe the documentation site does not publish (UNPUBLISHED_RECIPES), are documents a
self-hosted export drops, so the checks that read them are private:
tests/internal/test_integrations_evidence.py. Whether the
page is still the manifest's current rendering is a separate, private check:
tests/internal/test_site_integrations.py's test_the_rendered_pages_are_not_stale runs
scripts/render_integrations.py --check, which also compares the site register a self-hosted
export drops, so it cannot run there.
"""

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "integrations" / "manifest.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "integrations" / "manifest.schema.json").read_text(encoding="utf-8"))
ENTRIES = {entry["id"]: entry for entry in MANIFEST["integrations"]}
COMMERCIAL_WORDS = ("supported", "certified", "verified")
# The recipes a self-hosted export drops: a document under docs/ leaves only if the
# documentation site publishes it, and these are not published (none today). Every other
# recipe is checked here, so a published recipe that goes missing fails in the export too.
# tests/internal/test_integrations_evidence.py holds this set equal to the recipes under docs/
# that docs-site/publish.json does not publish, and checks that each exists.
UNPUBLISHED_RECIPES: frozenset[str] = frozenset()
TRIAL_FIELDS = ("Host", "Version", "Date", "Transport", "Gateway commit", "Fixture seed")
TRIALS = sorted(
    (entry_id, entry["evidence"]["trial"])
    for entry_id, entry in ENTRIES.items()
    if entry["evidence"]["trial"]
)


def test_the_manifest_matches_its_schema_and_ids_are_unique():
    jsonschema.validate(MANIFEST, SCHEMA)
    assert len(ENTRIES) == len(MANIFEST["integrations"])
    assert {entry["placement"] for entry in ENTRIES.values()} == {"Execute", "Gate", "Monitor"}


def node_id_exists(node_id):
    """The module exists and defines the test function (parametrized ids match by name).

    A cheap per-row guard that names the offending row. What the evidence claim actually
    rests on is collection, below: a function can be present in a file and still not be a
    test the suite runs.
    """
    module, _, function = node_id.partition("::")
    path = ROOT / module
    if not path.exists():
        return False
    name = function.split("[", 1)[0]
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(isinstance(node, ast.FunctionDef) and node.name == name for node in ast.walk(tree))


@pytest.mark.parametrize("entry_id", sorted(ENTRIES))
def test_each_row_claims_only_what_its_evidence_supports(entry_id):
    entry = ENTRIES[entry_id]
    versions, evidence = entry["versions"], entry["evidence"]
    if entry["state"] == "research-only":
        assert entry["mode"] == "Unknown", entry_id
        assert all(value is None for value in versions.values()), entry_id
        assert evidence["tests"] == [] and evidence["trial"] is None, entry_id
    elif entry["state"] == "fixture-tested":
        assert entry["mode"] != "Unknown" and evidence["tests"], entry_id
        for node in evidence["tests"]:
            assert node_id_exists(node), (entry_id, node)
        assert versions["execbound"] is not None, entry_id
    else:
        assert evidence["trial"], entry_id
    if entry["recipe"] is not None and entry["recipe"] not in UNPUBLISHED_RECIPES:
        assert (ROOT / entry["recipe"]).exists(), (entry_id, entry["recipe"])
    lowered = json.dumps(entry).lower()
    for word in COMMERCIAL_WORDS:
        assert re.search(rf"\b{word}\b", lowered) is None, (entry_id, word)


def test_every_test_a_row_names_is_one_this_suite_collects():
    """A fixture-tested row says CI runs that path, so the node ids have to be collectable.

    pytest exits 4 when a node id matches nothing, even where other ids on the same command
    line matched, so one collection over every id the manifest names is the whole check. It
    is the only thing that catches a test renamed or moved in one pull request while the
    manifest keeps citing where it used to be, which reading the file cannot.
    """
    nodes = sorted({node for entry in ENTRIES.values() for node in entry["evidence"]["tests"]})
    assert nodes, "no row names a test at all, which cannot be right"
    collected = subprocess.run(  # noqa: S603 - this interpreter, ids from our own manifest
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:randomly", *nodes],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert collected.returncode == 0, collected.stdout[-4000:] + collected.stderr[-2000:]
    for node in nodes:
        assert node.split("[", 1)[0] in collected.stdout, (node, collected.stdout[-2000:])


def test_sdk_versions_equal_the_pins():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    legacy = (ROOT / "tests" / "mcp-legacy.txt").read_text(encoding="utf-8")
    client = (ROOT / "clients" / "python" / "pyproject.toml").read_text(encoding="utf-8")
    official = re.search(r'"mcp==([^"]+)"', pyproject)[1]
    maintained = re.search(r"^mcp==(\S+)", legacy, re.M)[1]
    package = re.search(r'^version = "([^"]+)"', client, re.M)[1]
    assert ENTRIES["mcp-official-sdk"]["versions"]["sdk"] == official
    assert ENTRIES["mcp-maintained-client"]["versions"]["sdk"] == maintained
    assert ENTRIES["execbound-client-http"]["versions"]["sdk"] == package
    # The tool examples' rows name the SDK versions the hash-locked set installs, which is
    # what tests/test_sdk_examples.py ran them on.
    examples = (ROOT / "tests" / "sdk-examples.txt").read_text(encoding="utf-8")
    for entry_id, package_name in (
        ("openai-agents-sdk-tool", "openai-agents"),
        ("claude-agent-sdk-tool", "claude-agent-sdk"),
    ):
        pinned = re.search(rf"^{package_name}==(\S+)", examples, re.M)[1]
        assert ENTRIES[entry_id]["versions"]["sdk"] == pinned, entry_id


@pytest.mark.docs
def test_the_integrations_page_has_no_commercial_words_and_its_links_resolve():
    """docs/INTEGRATIONS.md is exported, so its own content is checked here even though
    whether it is still the manifest's current rendering is not: that needs the private
    renderer, so it stays in tests/internal/test_site_integrations.py instead.
    """
    page = (ROOT / "docs" / "INTEGRATIONS.md").read_text(encoding="utf-8")
    for link in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", page):
        if link.startswith("http"):
            continue
        assert (ROOT / "docs" / link).exists() or (ROOT / link).exists(), link
    lowered = page.lower()
    for word in COMMERCIAL_WORDS:
        assert re.search(rf"\b{word}\b", lowered) is None, word


@pytest.mark.docs
@pytest.mark.parametrize(("entry_id", "trial"), TRIALS, ids=[entry_id for entry_id, _ in TRIALS])
def test_a_trial_a_row_names_is_a_record_with_the_interview_fields(entry_id, trial):
    """A trial record is checked wherever a row names one, not only where the state depends
    on it: a row that cites a record nobody can read is the same empty claim either way."""
    record = ROOT / trial
    assert record.exists(), (entry_id, trial)
    text = record.read_text(encoding="utf-8")
    for field in TRIAL_FIELDS:
        assert re.search(rf"^{field}:", text, re.M), (entry_id, field)
    assert "## Scenarios" in text, entry_id
