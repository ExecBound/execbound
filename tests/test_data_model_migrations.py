# SPDX-License-Identifier: AGPL-3.0-only
"""docs/DATA_MODEL.md's migration history is one table with a row for every migration, in order.

The table broke twice without a test noticing: a paragraph landed between its rows, so every row
after it rendered as that paragraph's text, and nine migrations never got a row. Each row links
its revision's file, so the table is read against migrations/versions/ itself. Its last row's
count of forced-RLS tables is read against the database the migrations build, and no row's count
is lower than the one before it.
"""

import re
from pathlib import Path

import pytest
from sqlalchemy import text

from execbound.db import SCHEMA_REVISION

# Reads a document, so it carries `docs` and `pytest -m docs` selects it (#748).
pytestmark = pytest.mark.docs

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "DATA_MODEL.md"
VERSIONS = ROOT / "migrations" / "versions"
ROW = re.compile(r"^\| \[(\d{4}_\w+)\]\(\.\./migrations/versions/\1\.py\) \| .+ \| (\d+) \|$")


def history() -> list[str]:
    lines = DOCUMENT.read_text(encoding="utf-8").splitlines()
    start = lines.index("## Migration history")
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## "))
    return lines[start + 1 : end]


def history_table(section: list[str]) -> list[str]:
    """The table's lines, from its header to the first line that is not a row."""
    first = next(i for i, line in enumerate(section) if line.startswith("| Revision |"))
    table: list[str] = []
    for line in section[first:]:
        if not line.startswith("|"):
            break
        table.append(line)
    return table


def test_the_migration_history_is_one_table_with_a_row_for_every_migration_in_order():
    section = history()
    table = history_table(section)
    rows = table[2:]

    # A paragraph between two rows would leave the rows after it outside this one block.
    assert sum(line.startswith("|") for line in section) == len(table)
    assert [row[:80] for row in rows if not ROW.match(row)] == []
    revisions = [match.group(1) for row in rows if (match := ROW.match(row))]
    assert revisions == sorted(path.stem for path in VERSIONS.glob("0*.py"))


def test_the_forced_rls_count_never_falls_from_one_row_to_the_next():
    """No migration in the history drops a table or leaves one no longer forcing row security
    (the backfills that lift FORCE restore it in the same migration), so a row whose count is
    lower than the row before it is a mistyped count. A migration that does lower it changes
    this test in the same change, and says why."""
    rows = [match for row in history_table(history())[2:] if (match := ROW.match(row))]
    falls = [
        (before.group(1), int(before.group(2)), after.group(1), int(after.group(2)))
        for before, after in zip(rows, rows[1:], strict=False)
        if int(after.group(2)) < int(before.group(2))
    ]
    assert falls == []


def test_the_last_row_counts_the_forced_rls_tables_of_the_head_schema(admin_engine):
    """Only the head row is read against a database. The earlier rows would each need a
    schema upgraded one revision at a time, and they describe revisions that no longer
    change."""
    last = ROW.match(history_table(history())[-1])
    assert last is not None, "the table's last line is not a migration row"
    assert last.group(1) == SCHEMA_REVISION, f"the last row is {last.group(1)}"
    with admin_engine.connect() as conn:
        revision = conn.execute(
            text("SELECT version_num FROM execbound.alembic_version")
        ).scalar_one()
        forced = conn.execute(
            text(
                "SELECT count(*) FROM pg_class WHERE relnamespace = 'execbound'::regnamespace "
                "AND relkind IN ('r', 'p') AND relforcerowsecurity"
            )
        ).scalar_one()
    assert revision == SCHEMA_REVISION
    assert int(last.group(2)) == forced, f"the head schema has {forced} forced-RLS tables"
