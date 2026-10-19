# SPDX-License-Identifier: AGPL-3.0-only
"""No two of the console's pages claim the same selector (#333).

When each page appended its rules to one stylesheet, a name two pages both wanted was settled
by whichever block the file happened to end with, silently and with every test green. Ten such
collisions were found and fixed by hand, among them `.figures`, `.rules`, `.row-actions`,
`.explain` and a `.notice` in the monitoring pages that was overriding the approval page's
tone modifiers so every notice read amber. This is that rule made structural rather than
remembered.

`app.css` is divided by `/* @block <name> ... */` markers. A block may appear in several
regions (the shell's furniture is interleaved with the pages that were written against it)
and is the union of its own. `kit` holds everything a shared component renders or more than
one page uses; every other block is one page's. A selector may be declared as often as its
own block likes and never in two.
"""

import re
from collections import defaultdict
from pathlib import Path

STYLESHEET = Path(__file__).resolve().parents[1] / "console" / "src" / "styles" / "app.css"
MARKER = re.compile(r"^\s*/\*\s*@block\s+([a-z]+)\b")
SELECTOR = re.compile(r"^\s*([.#a-zA-Z\[][^{}@]*?)\s*\{")


def owners() -> dict[str, set[str]]:
    """Every selector in the file, with the blocks that declare it."""
    lines = STYLESHEET.read_text(encoding="utf-8").splitlines()
    found: dict[str, set[str]] = defaultdict(set)
    block: str | None = None
    depth = 0
    for line in lines:
        marker = MARKER.match(line)
        if marker:
            block = marker.group(1)
        # Depth 0 is a top-level rule; depth 1 with an indent is one inside a media query,
        # which belongs to whatever block wrote it just the same.
        if depth == 0 or (depth == 1 and line.startswith("  ")):
            rule = SELECTOR.match(line)
            if rule is not None and not rule.group(1).lstrip().startswith("@"):
                assert block is not None, f"a rule before the first @block marker: {line!r}"
                for part in rule.group(1).split(","):
                    if part.strip():
                        found[part.strip()].add(block)
        depth += line.count("{") - line.count("}")
    return found


def test_the_stylesheet_is_divided_into_named_blocks():
    named = {block for blocks in owners().values() for block in blocks}
    assert "kit" in named, "the shared furniture has no block of its own"
    assert len(named) >= 6, named


def test_no_selector_is_claimed_by_two_blocks():
    """A name two pages both want belongs to the kit, defined once, or is prefixed."""
    shared = {selector: sorted(blocks) for selector, blocks in owners().items() if len(blocks) > 1}
    assert shared == {}, f"claimed by more than one block: {shared}"


def test_every_block_declares_something():
    counts: dict[str, int] = defaultdict(int)
    for blocks in owners().values():
        for block in blocks:
            counts[block] += 1
    empty = [block for block, count in counts.items() if count == 0]
    assert empty == [], empty


RULE = re.compile(r"^\s*([^{}@/\s][^{}]*?)\s*\{([^{}]*)\}\s*$")


def declared(selector: str) -> set[str]:
    """The declarations of every one-line rule whose selector list names `selector`."""
    found: set[str] = set()
    for line in STYLESHEET.read_text(encoding="utf-8").splitlines():
        rule = RULE.match(line)
        if rule and selector in (part.strip() for part in rule.group(1).split(",")):
            found |= {item.strip() for item in rule.group(2).split(";") if item.strip()}
    return found


def test_a_box_marked_unavailable_is_dimmed_as_an_unavailable_button_is():
    """A checkbox kept focusable while its change is out is `aria-disabled`, not `disabled`,
    and must not look clickable: it takes the unavailable button's opacity and cursor."""
    button = declared('.btn[aria-disabled="true"]')
    assert button == {"opacity: 0.55", "cursor: default"}
    assert declared('input[aria-disabled="true"]') == button
