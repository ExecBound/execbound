# SPDX-License-Identifier: AGPL-3.0-only
"""Parse `docs/THREAT_MODEL.md` and print the next free threat id for each boundary.

The threat model cites tests, acceptance identifiers, other documents and its own residual
risks. An acceptance identifier names a row of `docs/ACCEPTANCE_TESTS.md`, or, written after
`hosted:`, a row of the hosted service's own inventory, which is not published.
`tests/test_threat_model_references.py` checks those citations, and it reads the
document through this module so that the parser exists once rather than twice.

`--next-ids` answers the question an implementing pull request asks: which id does my new
row take. It reports the highest id each boundary has used plus one, so a withdrawn row's
id is never handed out again, and it names any id that is unused or duplicated inside a
boundary rather than hiding it behind that number.
"""

from __future__ import annotations

import argparse
import ast
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
THREAT_MODEL = DOCS / "THREAT_MODEL.md"
ACCEPTANCE_TESTS = DOCS / "ACCEPTANCE_TESTS.md"
# The hosted service's own inventory. The self-hosted source tree does not carry it, so there a
# citation of one of its rows is evidence that tree cannot see.
HOSTED_ACCEPTANCE_TESTS = DOCS / "HOSTED_ACCEPTANCE_TESTS.md"
# What opens an evidence segment of hosted identifiers: "AC4, AC9; hosted: HF9, HF53; `tests/...`".
HOSTED_MARK = "hosted:"

# The section that holds the per-boundary tables, and the one that holds the residual risks.
THREATS_SECTION = "Threats and mitigations"
RESIDUAL_SECTION = "Residual risks"

# What a boundary table's header row has to say, in this order.
BOUNDARY_COLUMNS = ("ID", "STRIDE", "Threat", "Mitigation", "Evidence", "Status")
# Column positions inside a boundary row, once the row is split.
STRIDE, THREAT, MITIGATION, EVIDENCE, STATUS = 1, 2, 3, 4, 5

_SECTION = re.compile(r"^##\s+(?P<title>.+?)\s*$")
_BOUNDARY = re.compile(r"^###\s+(?P<id>B(?P<number>\d+)):\s*(?P<title>.+?)\s*$")
_THREAT_ID = re.compile(r"^T(?P<boundary>\d+)\.(?P<number>\d+)$")
_RISK_ID = re.compile(r"^R(?P<number>\d+)$")
_CODE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\[(?P<text>[^\]]*)\]\((?P<target>[^)]+)\)")
# "see R7", and the one status that names two risks: "see R19, R20".
_RISK_REFERENCE = re.compile(r"\bsee\s+(R\d+(?:\s*,\s*R\d+)*)")
# "CP4 to CP9" and "SR4 to SR8" abbreviate a run of acceptance identifiers.
_IDENTIFIER_RANGE = re.compile(r"^(?P<prefix>[A-Z]+)(?P<first>\d+) to (?P=prefix)(?P<last>\d+)$")
# An acceptance identifier is a letter prefix and an optional number, with an optional
# lettered variant: A, CC6, AX8b.
_IDENTIFIER = re.compile(r"^[A-Z]+\d*[a-z]?$")
# Acceptance rows are titled "Q / P1" where the id is the part before the slash.
_ACCEPTANCE_ID = re.compile(r"^(?P<id>[A-Za-z]+\d*[a-z]?)(?:\s*/.*)?$")
_LINK_SKIPPED = ("http://", "https://", "mailto:", "#")


@dataclass(frozen=True)
class ThreatRow:
    """One row of one boundary table."""

    boundary: str
    identifier: str
    number: int
    stride: str
    threat: str
    mitigation: str
    evidence: str
    status: str
    line: int


@dataclass(frozen=True)
class Boundary:
    """One `### B<n>` section under "Threats and mitigations"."""

    identifier: str
    number: int
    title: str
    columns: tuple[str, ...]
    rows: tuple[ThreatRow, ...]
    line: int


@dataclass(frozen=True)
class ResidualRisk:
    identifier: str
    number: int
    risk: str
    line: int


@dataclass(frozen=True)
class TestReference:
    """A ``tests/...`` path cited in the document, with the node when one is named.

    ``path`` is empty when the document wrote a bare ``::node`` continuation with no
    ``tests/`` path before it on the same line.
    """

    where: str
    path: str
    node: str | None
    line: int

    def __str__(self) -> str:
        return f"{self.path}::{self.node}" if self.node else self.path


@dataclass(frozen=True)
class AcceptanceReference:
    """An acceptance identifier cited in a row's evidence column, and whether it was written
    after `hosted:`, naming a row of the hosted inventory rather than the published one."""

    where: str
    identifier: str
    line: int
    hosted: bool = False


@dataclass(frozen=True)
class DocumentLink:
    """A Markdown link to a path rather than to a URL or an anchor."""

    where: str
    text: str
    target: str
    line: int

    @property
    def path(self) -> Path:
        """The file the link names, resolved the way a reader's browser resolves it."""
        return DOCS / self.target.split("#", 1)[0]


@dataclass(frozen=True)
class RiskReference:
    """A "see R<n>" written in a status cell or in prose."""

    where: str
    identifier: str
    line: int


@dataclass(frozen=True)
class ThreatModel:
    path: Path
    boundaries: tuple[Boundary, ...]
    residual_risks: tuple[ResidualRisk, ...]
    test_references: tuple[TestReference, ...]
    acceptance_references: tuple[AcceptanceReference, ...]
    links: tuple[DocumentLink, ...]
    risk_references: tuple[RiskReference, ...]

    @property
    def rows(self) -> tuple[ThreatRow, ...]:
        return tuple(row for boundary in self.boundaries for row in boundary.rows)


def split_row(line: str) -> list[str]:
    """Split one Markdown table row into its cells."""
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(set(cell) <= {"-", ":"} and cell for cell in cells)


def expand_identifiers(token: str) -> list[str]:
    """Expand "CP4 to CP9" into its identifiers, and leave any other token alone."""
    run = _IDENTIFIER_RANGE.match(token)
    if run is None:
        return [token]
    prefix = run.group("prefix")
    first, last = int(run.group("first")), int(run.group("last"))
    return [f"{prefix}{number}" for number in range(first, last + 1)]


def evidence_identifiers(evidence: str) -> list[tuple[str, bool]]:
    """The acceptance identifiers a row's evidence column opens with, each with whether it
    names the hosted inventory.

    A row writes its inventory identifiers first, separated by commas; then, in a segment of
    their own that opens with `hosted:`, any rows of the hosted inventory; and then a semicolon
    and the tests, documents or issues that carry the evidence. Either identifier segment may
    be absent. A segment is read as identifiers only when it holds neither backticks nor a
    link, and the first segment that is not read ends the reading.

    This is not every identifier a row can write. A row may also gloss a test file with the
    cases inside it, as `` `tests/test_key_rotation.py` (KR1 to KR8) ``. Those parenthetical
    prefixes belong to the test file rather than to the acceptance inventory, and eight of
    them — AF, KR, RC, AN, ES, SH, RS, SE — have no section in `docs/ACCEPTANCE_TESTS.md` at
    all, so reading them as inventory identifiers would report the document as broken for
    writing what it meant. They are deliberately out of scope here.
    """
    identifiers: list[tuple[str, bool]] = []
    for position, segment in enumerate(evidence.split(";")):
        segment = segment.strip()
        hosted = segment.startswith(HOSTED_MARK)
        if hosted:
            segment = segment.removeprefix(HOSTED_MARK)
        elif position:
            break
        if "`" in segment or "](" in segment:
            break
        for token in segment.split(","):
            token = token.strip()
            if not token:
                continue
            for identifier in expand_identifiers(token):
                if _IDENTIFIER.match(identifier):
                    identifiers.append((identifier, hosted))
    return identifiers


def line_test_references(where: str, line_number: int, text: str) -> list[TestReference]:
    """The ``tests/...`` citations on one line, binding each ``::node`` continuation.

    A row that names two nodes of one file writes the second as ``::node``, so a bare
    continuation belongs to the last ``tests/`` path written before it on the same line.
    """
    references: list[TestReference] = []
    current = ""
    for token in _CODE.findall(text):
        if token.startswith("tests/"):
            path, _, node = token.partition("::")
            current = path
            references.append(TestReference(where, path, node or None, line_number))
        elif token.startswith("::"):
            references.append(TestReference(where, current, token[2:], line_number))
    return references


def parse_threat_model(path: Path = THREAT_MODEL) -> ThreatModel:
    """Read the threat model into boundaries, residual risks and the references it makes."""
    section = ""
    boundary_id = ""
    boundary_number = 0
    boundary_title = ""
    boundary_line = 0
    columns: tuple[str, ...] = ()
    rows: list[ThreatRow] = []
    boundaries: list[Boundary] = []
    risks: list[ResidualRisk] = []
    tests: list[TestReference] = []
    acceptance: list[AcceptanceReference] = []
    links: list[DocumentLink] = []
    risk_references: list[RiskReference] = []

    def close_boundary() -> None:
        nonlocal rows, columns
        if boundary_id:
            boundaries.append(
                Boundary(
                    boundary_id,
                    boundary_number,
                    boundary_title,
                    columns,
                    tuple(rows),
                    boundary_line,
                )
            )
        rows, columns = [], ()

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        heading = _SECTION.match(line)
        if heading is not None:
            close_boundary()
            boundary_id, boundary_number, boundary_title, boundary_line = "", 0, "", 0
            section = heading.group("title")
        boundary = _BOUNDARY.match(line)
        if boundary is not None and section == THREATS_SECTION:
            close_boundary()
            boundary_id = boundary.group("id")
            boundary_number = int(boundary.group("number"))
            boundary_title = boundary.group("title")
            boundary_line = line_number

        where = f"line {line_number}"
        if line.startswith("|"):
            cells = split_row(line)
            if not is_separator(cells):
                identifier = cells[0]
                if section == THREATS_SECTION and boundary_id:
                    if identifier == BOUNDARY_COLUMNS[0] and not columns:
                        columns = tuple(cells)
                    threat = _THREAT_ID.match(identifier)
                    if threat is not None:
                        where = identifier
                        rows.append(
                            ThreatRow(
                                boundary=boundary_id,
                                identifier=identifier,
                                number=int(threat.group("number")),
                                stride=cells[STRIDE] if len(cells) > STRIDE else "",
                                threat=cells[THREAT] if len(cells) > THREAT else "",
                                mitigation=cells[MITIGATION] if len(cells) > MITIGATION else "",
                                evidence=cells[EVIDENCE] if len(cells) > EVIDENCE else "",
                                status=cells[STATUS] if len(cells) > STATUS else "",
                                line=line_number,
                            )
                        )
                        acceptance.extend(
                            AcceptanceReference(identifier, name, line_number, hosted)
                            for name, hosted in evidence_identifiers(rows[-1].evidence)
                        )
                elif section == RESIDUAL_SECTION:
                    risk = _RISK_ID.match(identifier)
                    if risk is not None:
                        where = identifier
                        risks.append(
                            ResidualRisk(
                                identifier=identifier,
                                number=int(risk.group("number")),
                                risk=cells[1] if len(cells) > 1 else "",
                                line=line_number,
                            )
                        )

        tests.extend(line_test_references(where, line_number, line))
        for link in _LINK.finditer(line):
            target = link.group("target")
            if not target.startswith(_LINK_SKIPPED):
                links.append(DocumentLink(where, link.group("text"), target, line_number))
        for phrase in _RISK_REFERENCE.findall(line):
            for name in re.findall(r"R\d+", phrase):
                risk_references.append(RiskReference(where, name, line_number))

    close_boundary()
    return ThreatModel(
        path=path,
        boundaries=tuple(boundaries),
        residual_risks=tuple(risks),
        test_references=tuple(tests),
        acceptance_references=tuple(acceptance),
        links=tuple(links),
        risk_references=tuple(risk_references),
    )


def acceptance_inventory(path: Path = ACCEPTANCE_TESTS) -> tuple[frozenset[str], frozenset[str]]:
    """An acceptance inventory's row identifiers, and the group prefixes they form. The hosted
    inventory is read by passing `HOSTED_ACCEPTANCE_TESTS`; the two are never merged."""
    rows: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = split_row(line)
        if is_separator(cells) or cells[0] in {"", "ID", "ID / patch"}:
            continue
        identifier = _ACCEPTANCE_ID.match(cells[0])
        if identifier is not None:
            rows.add(identifier.group("id"))
    groups = {re.sub(r"\d.*$", "", row) for row in rows if re.search(r"\d", row)}
    return frozenset(rows), frozenset(groups)


def defined_names(path: Path) -> frozenset[str]:
    """Every `def` and `async def` in a Python file, read without importing it."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    )


def next_ids(model: ThreatModel) -> list[tuple[str, str, str]]:
    """For each boundary and for the residual risks: the label, the next id and a note."""
    report: list[tuple[str, str, str]] = []
    for boundary in model.boundaries:
        numbers = [row.number for row in boundary.rows]
        report.append(
            (
                f"{boundary.identifier}: {boundary.title}",
                f"T{boundary.number}.{max(numbers) + 1}" if numbers else f"T{boundary.number}.1",
                sequence_note(f"T{boundary.number}.", numbers),
            )
        )
    numbers = [risk.number for risk in model.residual_risks]
    report.append(
        (
            RESIDUAL_SECTION,
            f"R{max(numbers) + 1}" if numbers else "R1",
            sequence_note("R", numbers),
        )
    )
    return report


def sequence_note(prefix: str, numbers: list[int]) -> str:
    """Name the unused and duplicated ids in one sequence, so the number above is trusted."""
    if not numbers:
        return ""
    notes: list[str] = []
    unused = [n for n in range(1, max(numbers) + 1) if n not in numbers]
    duplicated = sorted({n for n in numbers if numbers.count(n) > 1})
    if unused:
        notes.append("unused " + ", ".join(f"{prefix}{n}" for n in unused))
    if duplicated:
        notes.append("duplicated " + ", ".join(f"{prefix}{n}" for n in duplicated))
    return "; ".join(notes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--next-ids",
        action="store_true",
        help="print the next free threat id for each boundary, and the next residual risk id",
    )
    parser.add_argument(
        "--document", type=Path, default=THREAT_MODEL, help="the threat model to read"
    )
    arguments = parser.parse_args(argv)
    if not arguments.next_ids:
        parser.print_help()
        return 2

    model = parse_threat_model(arguments.document)
    report = next_ids(model)
    width = max(len(label) for label, _, _ in report)
    for label, identifier, note in report:
        line = f"{label.ljust(width)}  next {identifier}"
        print(f"{line}  ({note})" if note else line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
