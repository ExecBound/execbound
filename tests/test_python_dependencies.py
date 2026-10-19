# SPDX-License-Identifier: AGPL-3.0-only
"""`DEPENDENCIES.md` is the reviewed inventory; `uv.lock` and the installed metadata match it.

A third-party license is an obligation, and #122 records the runtime set with the license of
every distribution in it. `scripts/python_sbom.py` derives that set from the lockfile and
reads each license from the metadata that ships, so this file holds the document to both and
plants the cases the real tree does not have: a distribution the document omits, a license
the allowlist refuses, a license the metadata contradicts, strong copyleft, and a line left
behind by a dependency that is gone.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("python_sbom", ROOT / "scripts" / "python_sbom.py")
assert _spec is not None and _spec.loader is not None
python_sbom = importlib.util.module_from_spec(_spec)
sys.modules["python_sbom"] = python_sbom
_spec.loader.exec_module(python_sbom)

DOCUMENT = ROOT / "DEPENDENCIES.md"
LOCKFILE = ROOT / "uv.lock"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture(scope="module")
def resolved():
    return python_sbom.runtime(python_sbom.load_lock(LOCKFILE))


@pytest.fixture(scope="module")
def installed(resolved):
    return python_sbom.environment(sorted(resolved))


@pytest.fixture(scope="module")
def listed():
    return python_sbom.table(python_sbom.sections(DOCUMENT)[python_sbom.TABLE])


def entry(**overrides):
    base = {"version": "1.0", "source": {"registry": "r"}, "extras": set(), "marker": None}
    base.update(overrides)
    base.setdefault("hash", None)
    return base


def document(rows, *, exceptions=(), undeclared=(), first_party=()):
    """A document in the shape the script reads, built from names rather than prose."""
    return {
        python_sbom.TABLE: ["| Distribution | License | Why |", "| --- | --- | --- |"]
        + [f"| `{name}` | {licence} | Because. |" for name, licence in rows],
        python_sbom.EXCEPTIONS: [f"- `{name}`: the obligation." for name in exceptions],
        python_sbom.UNDECLARED: [f"- `{name}`: read by hand." for name in undeclared],
        python_sbom.FIRST_PARTY: [f"- `{name}`: ours." for name in first_party],
    }


# The committed tree


@pytest.mark.docs
def test_the_document_lists_every_runtime_distribution_and_nothing_else(resolved, listed):
    assert set(listed) == set(resolved), {
        "missing from the document": sorted(set(resolved) - set(listed)),
        "no longer a runtime distribution": sorted(set(listed) - set(resolved)),
    }


@pytest.mark.docs
def test_every_recorded_licence_is_the_one_the_installed_metadata_declares(installed, listed):
    """Where a distribution declares a license, the document repeats it rather than deciding."""
    assert installed, "nothing is installed, so this proves nothing"
    differing = {
        name: (declared, listed[name][0])
        for name, declared in installed.items()
        if listed[name][0] != declared
    }
    assert differing == {}, differing


@pytest.mark.docs
def test_a_distribution_with_no_readable_licence_is_recorded_by_hand(resolved, installed):
    """The five the script cannot read, and the one that is ours, are each named in a section
    of their own, so accepting a license nobody's metadata declares is always a written act."""
    document_sections = python_sbom.sections(DOCUMENT)
    recorded = python_sbom.named(document_sections[python_sbom.UNDECLARED])
    ours = python_sbom.named(document_sections[python_sbom.FIRST_PARTY])
    # Windows installs platform-specific distributions documented by hand on Linux.
    assert set(resolved) - set(installed) <= recorded | ours
    assert recorded | ours <= set(resolved)
    assert ours, "the client is first-party and should be named as such"


def test_nothing_a_release_installs_can_export_telemetry(resolved):
    """`opentelemetry-api` reaches the runtime through `fastapi` and `mcp`, and the API alone
    records nothing: with no provider configured every span, metric and log record is a no-op.
    FastAPI 0.142 configures OTLP export at startup from the `OTEL_EXPORTER_OTLP_*` variables,
    but only through the SDK and the HTTP exporter, which its `opentelemetry` and `standard`
    extras bring and this project never asks for; without them it logs a warning and exports
    nothing. DEPENDENCIES.md says nothing exports, and this holds the runtime set to it."""
    assert "opentelemetry-api" in resolved
    exporting = sorted(
        name
        for name in resolved
        if name.startswith("opentelemetry-") and name != "opentelemetry-api"
    )
    assert exporting == []


@pytest.mark.docs
def test_the_committed_tree_passes_and_writes_a_bill_of_materials(tmp_path):
    output = tmp_path / "sbom-python.cdx.json"
    code = python_sbom.main(
        [
            "--lockfile",
            str(LOCKFILE),
            "--dependencies",
            str(DOCUMENT),
            "--output",
            str(output),
            "--revision",
            "abc123",
        ]
    )
    assert code == 0
    bom = json.loads(output.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["version"] == "abc123"
    names = [component["name"] for component in bom["components"]]
    assert names == sorted(names) and len(names) == len(set(names))
    for component in bom["components"]:
        assert component["purl"] == f"pkg:pypi/{component['name']}@{component['version']}"
    # A component with no license to name carries none, rather than one called "none declared".
    for component in bom["components"]:
        for declaration in component.get("licenses", []):
            value = declaration.get("expression") or declaration["license"]["id"]
            assert value != python_sbom.NONE_DECLARED, component["name"]


# What the document has to account for


def test_a_runtime_distribution_the_document_omits_is_refused():
    problems = python_sbom.findings({"thing": entry()}, {"thing": "MIT"}, document([]))
    assert problems == ["thing is a runtime distribution and DEPENDENCIES.md omits it"]


def test_a_licence_outside_the_allowlist_needs_a_named_exception():
    resolved, installed = {"thing": entry()}, {"thing": "MPL-2.0"}
    (problem,) = python_sbom.findings(resolved, installed, document([("thing", "MPL-2.0")]))
    assert "not named under" in problem and "License exceptions" in problem
    excepted = document([("thing", "MPL-2.0")], exceptions=["thing"])
    assert python_sbom.findings(resolved, installed, excepted) == []


def test_strong_copyleft_is_refused_even_when_the_document_excepts_it():
    """An exception covers a notice a distributor ships. It does not cover the source of a
    combined work, which is a license decision and never a line in a dependency document."""
    for licence in ("GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0"):
        excepted = document([("thing", licence)], exceptions=["thing"])
        (problem,) = python_sbom.findings({"thing": entry()}, {"thing": licence}, excepted)
        assert problem == f"thing is {licence}, which no exception admits"
    # The weak copyleft in the real tree is not caught by that rule.
    assert not python_sbom.REFUSED.search("LGPL-3.0-only")
    assert not python_sbom.REFUSED.search("MPL-2.0")


def test_a_recorded_licence_the_metadata_contradicts_is_refused():
    """The document may record a license the metadata does not carry; it may not overrule one
    the metadata does carry, which is how a document goes quietly stale after an upgrade."""
    (problem,) = python_sbom.findings(
        {"thing": entry()}, {"thing": "LGPL-3.0-only"}, document([("thing", "MIT")])
    )
    assert problem == "thing declares LGPL-3.0-only and DEPENDENCIES.md records MIT"


def test_a_distribution_with_no_metadata_must_be_recorded_or_named_as_ours():
    rows = [("thing", "BSD-3-Clause")]
    (problem,) = python_sbom.findings({"thing": entry()}, {}, document(rows))
    assert "declares no license here" in problem
    assert python_sbom.findings({"thing": entry()}, {}, document(rows, undeclared=["thing"])) == []
    ours = entry(source={"editable": "clients/python"})
    (problem,) = python_sbom.findings({"thing": ours}, {}, document(rows))
    assert "is ours and is not named" in problem
    assert python_sbom.findings({"thing": ours}, {}, document(rows, first_party=["thing"])) == []


def test_a_line_left_behind_by_a_dependency_that_is_gone_is_refused():
    stale = document([("thing", "MIT"), ("removed", "MIT")], exceptions=["also-removed"])
    problems = python_sbom.findings({"thing": entry()}, {"thing": "MIT"}, stale)
    assert problems == [
        "also-removed is in DEPENDENCIES.md and is not a runtime distribution",
        "removed is in DEPENDENCIES.md and is not a runtime distribution",
    ]


# Reading a license, and reading the lockfile


@pytest.mark.parametrize(
    ("expression", "ok"),
    [
        ("MIT", True),
        ("Apache-2.0 OR BSD-3-Clause", True),
        ("MIT AND PSF-2.0", True),
        ("MIT-0", True),
        ("LGPL-3.0-only", False),
        ("MPL-2.0", False),
        ("MIT AND MPL-2.0", False),
        ("MPL-2.0 OR MIT", True),
        ("", False),
    ],
)
def test_the_allowlist_reads_an_expression_the_way_the_expression_reads(expression, ok):
    assert python_sbom.allowed(expression) is ok


def test_a_family_name_is_not_read_as_a_licence():
    """`License: BSD License` says which family, not which license, and two of the BSD
    licenses differ in what they oblige. The script refuses to guess; the document records
    which one the wheel's own text is."""
    assert python_sbom.EXPRESSION.match("BSD-3-Clause")
    assert not python_sbom.EXPRESSION.match("BSD License")
    assert not python_sbom.EXPRESSION.match("Python Software Foundation License")


@pytest.mark.parametrize("family", ["BSD", "PSF"])
def test_legacy_family_abbreviations_require_reviewed_license_text(monkeypatch, family):
    monkeypatch.setattr(python_sbom.metadata, "metadata", lambda _: {"License": family})
    assert python_sbom.declared("example") is None


def fixture_lock():
    return {
        "package": [
            {
                "name": python_sbom.PROJECT,
                "source": {"virtual": "."},
                "dependencies": [{"name": "direct", "extra": ["asked"]}],
                "dev-dependencies": {
                    python_sbom.RELEASE_GROUP: [{"name": "shipped"}],
                    "dev": [{"name": "tooling"}],
                },
            },
            {
                "name": "direct",
                "version": "1.0",
                "source": {"registry": "r"},
                "dependencies": [{"name": "plain"}],
                "optional-dependencies": {
                    "asked": [{"name": "wanted"}],
                    "not-asked": [{"name": "unwanted"}],
                },
                "sdist": {"hash": DIGEST},
                "wheels": [{"hash": "sha256:" + "b" * 64}, {"hash": "sha256:" + "c" * 64}],
            },
            {
                "name": "plain",
                "version": "2.0",
                "source": {"registry": "r"},
                "dependencies": [{"name": "windows-only", "marker": "sys_platform == 'win32'"}],
                "wheels": [{"hash": DIGEST}],
            },
            {"name": "wanted", "version": "3.0", "source": {"registry": "r"}},
            {"name": "unwanted", "version": "4.0", "source": {"registry": "r"}},
            {"name": "shipped", "version": "5.0", "source": {"editable": "clients/python"}},
            {"name": "tooling", "version": "6.0", "source": {"registry": "r"}},
            {
                "name": "windows-only",
                "version": "7.0",
                "source": {"registry": "r"},
                "wheels": [{"hash": "sha256:" + "d" * 64}, {"hash": "sha256:" + "e" * 64}],
            },
        ]
    }


def test_the_set_is_what_a_release_installs_and_not_what_a_developer_has():
    """An extra the project did not ask for brings nothing, and the development group is not
    a runtime dependency: both are the difference between the wheel and a checkout."""
    found = python_sbom.runtime(fixture_lock())
    assert set(found) == {"direct", "plain", "wanted", "shipped", "windows-only"}
    assert found["shipped"]["source"] == {"editable": "clients/python"}
    assert found["windows-only"]["marker"] == "sys_platform == 'win32'"
    assert found["plain"]["marker"] is None


def test_the_recorded_digest_is_the_one_that_describes_the_distribution():
    """The sdist's, where the lock has one. Otherwise a single wheel's, because one wheel of
    many is a build for one platform and does not describe what was installed."""
    found = python_sbom.runtime(fixture_lock())
    assert found["direct"]["hash"] == DIGEST.removeprefix("sha256:")
    assert found["plain"]["hash"] == DIGEST.removeprefix("sha256:")
    assert found["windows-only"]["hash"] is None
    assert found["wanted"]["hash"] is None


def test_the_bill_of_materials_marks_what_a_reader_would_otherwise_assume():
    found = python_sbom.runtime(fixture_lock())
    bom = python_sbom.bom(found, {"direct": "MIT", "plain": "Apache-2.0 OR MIT"}, "rev")
    components = {component["name"]: component for component in bom["components"]}
    assert components["direct"]["licenses"] == [{"license": {"id": "MIT"}}]
    assert components["plain"]["licenses"] == [{"expression": "Apache-2.0 OR MIT"}]
    assert "licenses" not in components["wanted"]
    assert {"name": "execbound:first-party", "value": "true"} in components["shipped"]["properties"]
    assert components["windows-only"]["properties"] == [
        {"name": "execbound:marker", "value": "sys_platform == 'win32'"}
    ]
