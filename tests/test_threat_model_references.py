# SPDX-License-Identifier: AGPL-3.0-only
"""`docs/THREAT_MODEL.md` cites tests, acceptance identifiers, documents and residual risks.

Its maintenance section requires a row in the same pull request as a new route, tool, page,
command, connector or authority migration (#269). Nothing checked those citations, so a test
renamed or an acceptance identifier withdrawn would leave a row pointing at nothing until a
reviewer happened to click it. These tests read the document through the same parser that
feeds `scripts/threat_model_index.py --next-ids`, so the helper an implementing pull request
uses and the check it has to pass read the document the same way.

A failure over a citation names the row it came from, the citation and the document line, so
the person who broke it does not have to search for it. Node citations are resolved with
`ast`, so no test module is imported to find out which nodes it defines.

Rows may cite tests under `tests/hosted/` and `tests/internal/`, which the self-hosted source
tree does not carry. Where a tree holds such a directory its citations are checked like any
other; where it does not, a citation of it is evidence this tree cannot see, so it is neither
failed nor skipped, and its node is not collected. A core test's citation is checked
everywhere, and a missing file fails both checks rather than skipping one.

Acceptance identifiers follow the same rule. One written after `hosted:` names a row of
`docs/HOSTED_ACCEPTANCE_TESTS.md`, checked where the tree carries that file and evidence it
cannot see where it does not. Any other is checked against `docs/ACCEPTANCE_TESTS.md` alone,
in every tree, so a citation this repository accepts is one the self-hosted tree accepts too.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

# Reads a document, so it carries `docs` and `pytest -m docs` selects it (#748).
pytestmark = pytest.mark.docs

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "threat_model_index", ROOT / "scripts" / "threat_model_index.py"
)
assert _spec is not None and _spec.loader is not None
threat_model_index = importlib.util.module_from_spec(_spec)
sys.modules["threat_model_index"] = threat_model_index
_spec.loader.exec_module(threat_model_index)

MODEL = threat_model_index.parse_threat_model()
ACCEPTANCE_ROWS, ACCEPTANCE_GROUPS = threat_model_index.acceptance_inventory()
# The hosted service's inventory where this tree carries it, and None where it does not.
HOSTED_INVENTORY = (
    threat_model_index.acceptance_inventory(threat_model_index.HOSTED_ACCEPTANCE_TESTS)
    if threat_model_index.HOSTED_ACCEPTANCE_TESTS.is_file()
    else None
)

# The status words the document uses, each optionally qualified by ", in review" and by a
# ", see R<n>" that points at a residual risk. A new word belongs in the status table at the
# top of the document, and here, before a row carries it.
STATUS_WORDS = ("Verified", "Partial", "Open", "Accepted")
STATUS = re.compile(
    r"^(?P<word>" + "|".join(STATUS_WORDS) + r")(?:, in review)?(?:, see R\d+(?:, R\d+)*)?$"
)

# One row carries a status that splits across two of those words because the row itself
# splits. It is recorded verbatim against its row id, so a status of this shape on any other
# row, or a new wording on this one, fails rather than passing quietly.
COMPOUND_STATUSES = frozenset(
    {
        ("T5.4", "Verified for facts and incidents; Accepted for canonical mapping, see R10"),
    }
)


# Test directories a tree may leave out: the hosted service's plugin tests and the tests of
# files that are not published. The trailing slash keeps a look-alike such as `tests/hostedx/`
# a core path. `tests/test_boundary.py` joins its twin's values as paths; this copy is a
# `startswith` prefix, so it carries the slash itself.
PRIVATE_TEST_DIRECTORIES = ("tests/hosted/", "tests/internal/")


def label(where: str) -> str:
    """Name the row a reference came from, or the document line when it came from prose."""
    return where if where.startswith(("T", "R")) else f"{MODEL.path.name} {where}"


def checkable(path: str, root: Path = ROOT) -> bool:
    """Whether this tree can check a citation of `path`: a core test always, a test under a
    private directory only where that directory is present."""
    directory = next((d for d in PRIVATE_TEST_DIRECTORIES if path.startswith(d)), None)
    return directory is None or (root / directory).is_dir()


def file_problem(reference: threat_model_index.TestReference, root: Path = ROOT) -> str | None:
    """What is wrong with a cited test file, or None when nothing is or the tree cannot see it."""
    if not reference.path:
        return (
            f"{label(reference.where)} writes `::{reference.node}` with no "
            f"tests/ path before it on line {reference.line}"
        )
    if checkable(reference.path, root) and not (root / reference.path).is_file():
        return (
            f"{label(reference.where)} cites {reference.path}, "
            f"which is not a file (line {reference.line})"
        )
    return None


def node_references(
    model: threat_model_index.ThreatModel, root: Path = ROOT
) -> list[threat_model_index.TestReference]:
    """The node citations this tree can check."""
    return [r for r in model.test_references if r.node and r.path and checkable(r.path, root)]


def node_problem(reference: threat_model_index.TestReference, root: Path = ROOT) -> str | None:
    """What is wrong with a cited node, or None. A missing file is a problem here too."""
    path = root / reference.path
    if not path.is_file():
        return (
            f"{label(reference.where)} cites {reference}, but {reference.path} "
            f"is not a file (line {reference.line})"
        )
    if reference.node not in threat_model_index.defined_names(path):
        return (
            f"{label(reference.where)} cites {reference}, but {reference.path} "
            f"defines no def or async def named {reference.node} (line {reference.line})"
        )
    return None


def boundary_parameters():
    return [pytest.param(boundary, id=boundary.identifier) for boundary in MODEL.boundaries]


def test_the_document_parsed_into_boundaries_rows_and_risks():
    """A parser that silently found nothing would make every check below vacuous."""
    assert len(MODEL.boundaries) >= 10, MODEL.boundaries
    assert len(MODEL.rows) >= 100, len(MODEL.rows)
    assert len(MODEL.residual_risks) >= 20, len(MODEL.residual_risks)
    assert MODEL.test_references and MODEL.acceptance_references
    # A tree that carries the hosted tests carries the hosted inventory they are evidence for.
    assert HOSTED_INVENTORY is not None or not (ROOT / "tests/hosted").is_dir()
    assert HOSTED_INVENTORY is None or HOSTED_INVENTORY[0], "the hosted inventory has no rows"
    assert MODEL.links and MODEL.risk_references


def cited_files():
    """One parameter per (row, file) pair; a row naming two nodes of one file cites it once."""
    seen: dict[tuple[str, str], object] = {}
    for reference in MODEL.test_references:
        seen.setdefault((reference.where, reference.path), reference)
    return [
        pytest.param(reference, id=f"{where}-{path.rsplit('/', 1)[-1] or 'unbound'}")
        for (where, path), reference in seen.items()
    ]


@pytest.mark.parametrize("reference", cited_files())
def test_cited_test_file_exists(reference):
    problem = file_problem(reference)
    assert problem is None, problem


@pytest.mark.parametrize(
    "reference",
    [
        pytest.param(r, id=f"{r.where}-{r.path.rsplit('/', 1)[-1]}::{r.node}")
        for r in node_references(MODEL)
    ],
)
def test_cited_test_node_is_defined(reference):
    problem = node_problem(reference)
    assert problem is None, problem


# A threat model in miniature: one row cites a core test, one a plugin test by node and one a
# private test by file, so the two checks above can be run against a tree with the private
# directories and a tree without them.
SIMULATED = """# Threat model

## Threats and mitigations

### B1: Simulated boundary

| ID | STRIDE | Threat | Mitigation | Evidence | Status |
| --- | --- | --- | --- | --- | --- |
| T1.1 | S | A | B | `tests/test_core.py::test_core` | Verified |
| T1.2 | S | A | B | `tests/hosted/test_plugin.py::test_plugin` | Verified |
| T1.3 | T | A | B | `tests/internal/test_rules.py` | Verified |
"""


def simulated_tree(root: Path, *, private: bool) -> threat_model_index.ThreatModel:
    """Write the miniature's tests under `root`, the private ones only when asked, and parse it."""
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_core.py").write_text("def test_core():\n    pass\n", encoding="utf-8")
    if private:
        for relative in ("tests/hosted/test_plugin.py", "tests/internal/test_rules.py"):
            path = root / relative
            path.parent.mkdir()
            path.write_text(f"def {path.stem}():\n    pass\n", encoding="utf-8")
    document = root / "THREAT_MODEL.md"
    document.write_text(SIMULATED, encoding="utf-8")
    return threat_model_index.parse_threat_model(document)


def test_a_private_citation_is_checked_where_its_directory_is_present(tmp_path):
    model = simulated_tree(tmp_path, private=True)
    core, plugin, rules = model.test_references
    assert [file_problem(r, tmp_path) for r in (core, plugin, rules)] == [None, None, None]
    assert node_references(model, tmp_path) == [core, plugin]
    assert [node_problem(r, tmp_path) for r in (core, plugin)] == [None, None]
    # Here the directory is part of the tree, so a citation that went stale in it fails.
    (tmp_path / "tests/hosted/test_plugin.py").unlink()
    assert "which is not a file" in (file_problem(plugin, tmp_path) or "")
    assert "is not a file" in (node_problem(plugin, tmp_path) or "")


def test_a_private_citation_is_evidence_this_tree_cannot_see_where_its_directory_is_absent(
    tmp_path,
):
    model = simulated_tree(tmp_path, private=False)
    core, plugin, rules = model.test_references
    assert [file_problem(r, tmp_path) for r in (core, plugin, rules)] == [None, None, None]
    assert node_references(model, tmp_path) == [core]
    # A core test is checked wherever the tree is, and a missing one fails, never skips.
    (tmp_path / "tests" / "test_core.py").unlink()
    assert "which is not a file" in (file_problem(core, tmp_path) or "")
    assert "is not a file" in (node_problem(core, tmp_path) or "")


def test_a_look_alike_directory_is_a_core_path(tmp_path):
    (tmp_path / "tests").mkdir()
    assert checkable("tests/test_x.py", tmp_path)
    assert checkable("tests/hostedx/test_x.py", tmp_path)
    assert not checkable("tests/hosted/test_x.py", tmp_path)
    assert not checkable("tests/internal/test_x.py", tmp_path)


Inventory = tuple[frozenset[str], frozenset[str]]


def acceptance_problem(
    reference: threat_model_index.AcceptanceReference,
    published: Inventory,
    hosted: Inventory | None,
) -> str | None:
    """What is wrong with a cited acceptance identifier, or None when nothing is or this tree
    cannot see the inventory it names."""
    if reference.hosted and hosted is None:
        return None
    rows, groups = hosted if reference.hosted and hosted is not None else published
    if reference.identifier in rows or reference.identifier in groups:
        return None
    document = "HOSTED_ACCEPTANCE_TESTS.md" if reference.hosted else "ACCEPTANCE_TESTS.md"
    kind = "hosted acceptance identifier" if reference.hosted else "acceptance identifier"
    return (
        f"{label(reference.where)} cites {kind} {reference.identifier}, which is neither a "
        f"row nor a group in docs/{document} (line {reference.line})"
    )


@pytest.mark.parametrize(
    "reference",
    [pytest.param(r, id=f"{r.where}-{r.identifier}") for r in MODEL.acceptance_references],
)
def test_cited_acceptance_identifier_is_in_its_inventory(reference):
    problem = acceptance_problem(reference, (ACCEPTANCE_ROWS, ACCEPTANCE_GROUPS), HOSTED_INVENTORY)
    assert problem is None, problem


def test_no_row_identifier_is_in_both_inventories():
    """One identifier names one row, so a citation cannot resolve in the inventory it did not
    mean. A tree without the hosted inventory has nothing to compare, and passes."""
    if HOSTED_INVENTORY is None:
        return
    shared = sorted(ACCEPTANCE_ROWS & HOSTED_INVENTORY[0])
    assert shared == [], "both inventories number the rows " + ", ".join(shared)


# Two inventories in miniature and a threat model citing each, so the check above can be run
# against a tree with the hosted inventory and a tree without it.
SIMULATED_INVENTORY = """| ID | Setup/action | Required result |
| --- | --- | --- |
| CC1 | A | B |
"""
SIMULATED_HOSTED_INVENTORY = """| ID | Scenario | Expected |
| --- | --- | --- |
| VS3 | A | B |
"""
SIMULATED_CITATIONS = """# Threat model

## Threats and mitigations

### B1: Simulated boundary

| ID | STRIDE | Threat | Mitigation | Evidence | Status |
| --- | --- | --- | --- | --- | --- |
| T1.1 | S | A | B | CC1; hosted: VS3; `tests/test_core.py` | Verified |
| T1.2 | S | A | B | hosted: VS9; `tests/hosted/test_plugin.py` | Verified |
| T1.3 | T | A | B | VS3; `tests/test_core.py` | Verified |
"""


@pytest.mark.parametrize("carried", [True, False], ids=["with-inventory", "without-inventory"])
def test_a_hosted_citation_is_checked_only_where_its_inventory_is_present(tmp_path, carried):
    document = tmp_path / "THREAT_MODEL.md"
    document.write_text(SIMULATED_CITATIONS, encoding="utf-8")
    (tmp_path / "published.md").write_text(SIMULATED_INVENTORY, encoding="utf-8")
    (tmp_path / "hosted.md").write_text(SIMULATED_HOSTED_INVENTORY, encoding="utf-8")
    model = threat_model_index.parse_threat_model(document)
    cited = [(r.identifier, r.hosted) for r in model.acceptance_references]
    assert cited == [("CC1", False), ("VS3", True), ("VS9", True), ("VS3", False)]
    published = threat_model_index.acceptance_inventory(tmp_path / "published.md")
    inventory = threat_model_index.acceptance_inventory(tmp_path / "hosted.md") if carried else None
    problems = [acceptance_problem(r, published, inventory) for r in model.acceptance_references]
    assert problems[:2] == [None, None]
    # A hosted row that does not exist fails only where the hosted inventory can be read.
    assert (problems[2] is None) is not carried
    # A hosted row cited without `hosted:` fails in both trees, so this repository's check
    # refuses what the self-hosted tree's would.
    assert "neither a row nor a group in docs/ACCEPTANCE_TESTS.md" in (problems[3] or "")


@pytest.mark.parametrize(
    "link",
    [pytest.param(link, id=f"{link.where}-{link.target}") for link in MODEL.links],
)
def test_document_link_resolves(link):
    assert link.path.exists(), (
        f"{label(link.where)} links to {link.target} "
        f"({link.path}), which does not exist (line {link.line})"
    )


@pytest.mark.parametrize(
    "reference",
    [pytest.param(r, id=f"{r.where}-{r.identifier}") for r in MODEL.risk_references],
)
def test_risk_reference_names_an_existing_residual_risk(reference):
    known = {risk.identifier for risk in MODEL.residual_risks}
    assert reference.identifier in known, (
        f"{label(reference.where)} says 'see {reference.identifier}', but "
        f"the residual risk table has no {reference.identifier} (line {reference.line})"
    )


# Unique and ascending, not contiguous. The document requires identifiers to stay stable so
# that issues and reviews can cite them, and stability means a withdrawn row leaves its number
# unused for good; a check that demanded contiguity would force the two rules to contradict
# each other the first time a row was withdrawn. Uniqueness is the half that citation actually
# needs, because two rows sharing an id cannot be cited apart. Ascending order is what catches
# an id taken out of sequence, which is how B4's missing T4.8 was found. A gap is left to
# `--next-ids`, which names every unused and duplicated id so a reader can tell a withdrawal
# from a mistake without a test having to guess which it is.
@pytest.mark.parametrize("boundary", boundary_parameters())
def test_boundary_threat_ids_are_unique_and_ascending(boundary):
    numbers = [row.number for row in boundary.rows]
    assert numbers, f"{boundary.identifier} has no threat rows"
    duplicated = sorted({n for n in numbers if numbers.count(n) > 1})
    assert not duplicated, f"{boundary.identifier} numbers more than one row " + ", ".join(
        f"T{boundary.number}.{n}" for n in duplicated
    )
    assert numbers == sorted(numbers), (
        f"{boundary.identifier} does not ascend in document order: it reads "
        + ", ".join(row.identifier for row in boundary.rows)
    )


def test_residual_risk_ids_are_unique_and_ascending():
    """Residual risks are cited by `see R<n>`, so they hold the rule the boundaries hold."""
    numbers = [risk.number for risk in MODEL.residual_risks]
    duplicated = sorted({n for n in numbers if numbers.count(n) > 1})
    assert not duplicated, "the residual risk table numbers more than one row " + ", ".join(
        f"R{n}" for n in duplicated
    )
    assert numbers == sorted(numbers), (
        "the residual risks do not ascend in document order: they read "
        + ", ".join(risk.identifier for risk in MODEL.residual_risks)
    )


@pytest.mark.parametrize("boundary", [pytest.param(b, id=b.identifier) for b in MODEL.boundaries])
def test_boundary_table_carries_the_six_columns(boundary):
    assert boundary.columns == threat_model_index.BOUNDARY_COLUMNS, (
        f"{boundary.identifier} (line {boundary.line}) has the columns "
        f"{list(boundary.columns)}, not {list(threat_model_index.BOUNDARY_COLUMNS)}"
    )


def test_no_blank_line_splits_a_table():
    """A blank line between two rows ends a Markdown table, and every row after it renders as
    raw pipes with no header, on GitHub and on the trust site. The parser above reads those
    lines as rows all the same, so without this nothing notices: five had split three tables."""
    lines = threat_model_index.THREAT_MODEL.read_text(encoding="utf-8").split("\n")
    split = [
        number + 1
        for number in range(1, len(lines) - 1)
        if lines[number] == ""
        and lines[number - 1].startswith("|")
        and lines[number + 1].startswith("|")
    ]
    assert split == [], f"blank lines inside a table at lines {split}"


@pytest.mark.parametrize("row", [pytest.param(r, id=r.identifier) for r in MODEL.rows])
def test_row_status_is_in_the_vocabulary(row):
    if (row.identifier, row.status) in COMPOUND_STATUSES:
        return
    assert STATUS.match(row.status), (
        f"{row.identifier} (line {row.line}) has status {row.status!r}; the vocabulary is "
        f"{', '.join(STATUS_WORDS)}, each optionally ', in review' and ', see R<n>', "
        "plus the two compound statuses this file records verbatim"
    )


@pytest.mark.parametrize("row", [pytest.param(r, id=r.identifier) for r in MODEL.rows])
def test_a_verified_row_carries_evidence(row):
    if not row.status.startswith("Verified"):
        return
    assert row.evidence, (
        f"{row.identifier} (line {row.line}) is Verified with an empty evidence column; "
        "a Verified row names the scenario or test that exercises its mitigation"
    )


def test_the_next_ids_report_covers_every_boundary_and_the_residual_risks():
    report = threat_model_index.next_ids(MODEL)
    assert len(report) == len(MODEL.boundaries) + 1
    labels = [label for label, _, _ in report]
    assert labels[-1] == threat_model_index.RESIDUAL_SECTION
    for boundary, (heading, identifier, _) in zip(MODEL.boundaries, report, strict=False):
        assert heading.startswith(f"{boundary.identifier}:")
        highest = max(row.number for row in boundary.rows)
        assert identifier == f"T{boundary.number}.{highest + 1}"
