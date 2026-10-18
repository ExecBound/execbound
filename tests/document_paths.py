# SPDX-License-Identifier: AGPL-3.0-only
"""Which files are documents, for the `docs` marker (#748).

A document is a Markdown file under `docs/`, at the repository's root, or under
`export/public/`, except the root's `DEPENDENCIES.md` and `THIRD_PARTY_NOTICES.md`: those are
written from and checked against the dependency records by checks of their own, so a change to
either is a change to code. The `docs` marker's guard (`tests/document_reads.py`) holds every
test that reads a document to carrying the marker, so `pytest -m docs` selects every test a
change to documents alone can break. A check that decides whether a change touches documents
alone uses this same rule; anything else, an image or a documentation site's source included,
is code.

Standard library only, so such a check can import it without the test environment.
"""

from pathlib import PurePosixPath

# Root Markdown files that are generated or checked by a step other than the tests: code.
CHECKED = frozenset({"DEPENDENCIES.md", "THIRD_PARTY_NOTICES.md"})


def is_document(path: str) -> bool:
    """Whether a path relative to the repository's root, written with `/`, is a document."""
    parts = PurePosixPath(path).parts
    if not parts or parts[-1].startswith(".") or PurePosixPath(path).suffix != ".md":
        return False
    if ".." in parts or parts[0] == "/":
        return False
    if len(parts) == 1:
        return parts[0] not in CHECKED
    return parts[0] == "docs" or parts[:2] == ("export", "public")
