# SPDX-License-Identifier: AGPL-3.0-only
"""The pages that stay server-rendered read the console's own tokens, and nothing else.

`tests/test_console_tokens.py` holds `console/public/tokens.css` to its WCAG 2.2 AA floors;
this holds the pages' stylesheet equal to that file. The blocks are copied rather than
imported so `/login` renders with no console build present, and copies drift, which is what
this refuses to let them do.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "src" / "execbound" / "surfaces" / "assets" / "app.css"
CONSOLE = ROOT / "console" / "public" / "tokens.css"
TOKEN = re.compile(r"(--eb-[a-z0-9-]+)\s*:\s*([^;]+);")
LITERAL = re.compile(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", re.IGNORECASE)
# The three blocks the console declares: light, dark and the live board's full-ink exception.
BLOCKS = (
    (r":root\s*\{([^}]*)\}", "light"),
    (r"@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}", "dark"),
    (r"\.ink\s*\{([^}]*)\}", "ink"),
)


def blocks(css: str) -> dict[str, dict[str, str]]:
    found = {}
    for pattern, name in BLOCKS:
        matches = re.findall(pattern, css)
        assert matches, f"no {name} token block"
        found[name] = dict(TOKEN.findall(matches[0]))
    return found


@pytest.mark.parametrize("scheme", ["light", "dark", "ink"])
def test_the_pages_tokens_are_the_consoles(scheme):
    """One token set, three copies of it, held equal value for value."""
    ours = blocks(PAGES.read_text(encoding="utf-8"))[scheme]
    theirs = blocks(CONSOLE.read_text(encoding="utf-8"))[scheme]
    assert theirs, f"the console declares no {scheme} tokens"
    for name, value in theirs.items():
        assert ours.get(name) == value, f"{scheme} {name}: pages {ours.get(name)!r} != {value!r}"


def test_no_colour_literal_appears_outside_the_token_blocks():
    css = PAGES.read_text(encoding="utf-8")
    outside = css
    for pattern, _ in BLOCKS:
        outside = re.sub(pattern + r"\s*\}?", "", outside)
    outside = re.sub(r"/\*.*?\*/", "", outside, flags=re.DOTALL)
    literals = [match.group(0) for match in LITERAL.finditer(outside)]
    assert literals == [], f"colour literals outside the token blocks: {literals}"


def test_the_type_is_the_consoles_own_packaged_files():
    """The pages take IBM Plex from the console build, under `font-src 'self'`."""
    css = PAGES.read_text(encoding="utf-8")
    faces = re.findall(r'src: url\("([^"]+)"\) format\("woff2"\);', css)
    assert len(faces) == 7, faces
    assert all(url.startswith("/console/fonts/IBMPlex") for url in faces), faces
    # A deployment with no build falls back to the system stack rather than to nothing.
    assert 'system-ui, "Segoe UI", sans-serif' in css
