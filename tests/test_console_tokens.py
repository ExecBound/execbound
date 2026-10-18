# SPDX-License-Identifier: AGPL-3.0-only
"""The console's tokens meet their contrast floors in both schemes, read from the file.

This reads `console/public/tokens.css`, which index.html loads before any script, and
`tests/test_page_tokens.py` holds the server-rendered pages' stylesheet equal to it. Every
documented pairing (#333) is held by name, so a token edit fails here in seconds, before a
browser is involved. Alpha tokens are composited over the surface they sit on before the ratio
is taken, which is what a browser draws.
"""

import re
from pathlib import Path

import pytest

TOKENS = Path(__file__).resolve().parents[1] / "console" / "public" / "tokens.css"
CONSOLE = Path(__file__).resolve().parents[1] / "console"

# (foreground, background, minimum ratio, composited over). 4.5 is AA for body text; 3.0 is AA
# for large text and for non-text indicators such as the focus ring and a badge's dot.
PAIRINGS = [
    ("--eb-text", "--eb-bg", 4.5, None),
    ("--eb-text", "--eb-side", 4.5, None),
    ("--eb-text", "--eb-surface", 4.5, None),
    ("--eb-text", "--eb-surface2", 4.5, None),
    ("--eb-muted", "--eb-bg", 4.5, None),
    ("--eb-muted", "--eb-surface", 4.5, None),
    ("--eb-muted", "--eb-surface2", 4.5, None),
    ("--eb-faint", "--eb-bg", 4.5, None),
    ("--eb-faint", "--eb-surface", 4.5, None),
    ("--eb-faint", "--eb-surface2", 4.5, None),
    ("--eb-on-accent", "--eb-accent", 4.5, None),
    ("--eb-accent-text", "--eb-bg", 4.5, None),
    ("--eb-accent-text", "--eb-surface", 4.5, None),
    ("--eb-accent-text", "--eb-accent-soft", 4.5, "--eb-surface"),
    ("--eb-accent", "--eb-bg", 3.0, None),
    ("--eb-accent", "--eb-surface", 3.0, None),
    ("--eb-accent", "--eb-side", 3.0, None),
    ("--eb-allow", "--eb-allow-bg", 4.5, "--eb-surface"),
    ("--eb-hold", "--eb-hold-bg", 4.5, "--eb-surface"),
    ("--eb-deny", "--eb-deny-bg", 4.5, "--eb-surface"),
    ("--eb-obs", "--eb-obs-bg", 4.5, "--eb-surface"),
    ("--eb-stale", "--eb-stale-bg", 4.5, "--eb-surface"),
    ("--eb-allow", "--eb-surface", 4.5, None),
    ("--eb-hold", "--eb-surface", 4.5, None),
    ("--eb-deny", "--eb-surface", 4.5, None),
    ("--eb-obs", "--eb-surface", 4.5, None),
    ("--eb-deny", "--eb-bg", 4.5, None),
    ("--eb-line2", "--eb-surface", 1.4, None),
]

REQUIRED = sorted({token for pairing in PAIRINGS for token in pairing[:2] if token})
HEX = re.compile(r"^#([0-9a-fA-F]{6})$")
RGBA = re.compile(r"^rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([0-9.]+)\s*\)$")
LITERAL = re.compile(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", re.IGNORECASE)


def blocks() -> dict[str, dict[str, str]]:
    css = TOKENS.read_text(encoding="utf-8")
    found = re.findall(r":root\s*\{([^}]*)\}", css)
    assert len(found) == 2, "expected one light and one dark :root block"
    light, dark = (dict(re.findall(r"(--eb-[a-z0-9-]+)\s*:\s*([^;]+);", b)) for b in found)
    assert "prefers-color-scheme: dark" in css.split(found[1])[0].rsplit(":root", 1)[0]
    return {
        "light": {k: v.strip() for k, v in light.items()},
        "dark": {k: v.strip() for k, v in dark.items()},
    }


def parse(value: str) -> tuple[float, float, float, float]:
    match = HEX.match(value)
    if match:
        digits = match.group(1)
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16), 1.0)
    match = RGBA.match(value)
    assert match, value
    return (
        float(match.group(1)),
        float(match.group(2)),
        float(match.group(3)),
        float(match.group(4)),
    )


def composite(colour: str, over: str) -> tuple[float, float, float]:
    r, g, b, a = parse(colour)
    br, bg, bb, _ = parse(over)
    return (r * a + br * (1 - a), g * a + bg * (1 - a), b * a + bb * (1 - a))


def luminance(rgb: tuple[float, float, float]) -> float:
    channels = [c / 255 for c in rgb]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def ratio(fore: tuple[float, float, float], back: tuple[float, float, float]) -> float:
    lighter, darker = sorted((luminance(fore), luminance(back)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_required_token_is_declared_in_both_schemes(scheme):
    tokens = blocks()[scheme]
    missing = [token for token in REQUIRED if token not in tokens]
    assert missing == [], f"{scheme}: {missing}"


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("fore,back,floor,over", PAIRINGS)
def test_documented_pairings_meet_their_floor(scheme, fore, back, floor, over):
    tokens = blocks()[scheme]
    ground = tokens[over] if over else tokens["--eb-surface"]
    background = composite(tokens[back], ground)
    foreground = composite(tokens[fore], tokens[back] if parse(tokens[back])[3] == 1.0 else ground)
    measured = ratio(foreground, background)
    assert measured >= floor, f"{scheme}: {fore} on {back} is {measured:.2f}, below {floor}"


def test_the_dark_block_redeclares_every_colour_and_nothing_else():
    light, dark = blocks()["light"], blocks()["dark"]
    colours = {name for name, value in light.items() if HEX.match(value) or RGBA.match(value)}
    shadows = {"--eb-shadow"}
    assert set(dark) == (colours | shadows), sorted(set(dark) ^ (colours | shadows))


def test_the_ink_block_is_the_dark_block_by_another_name():
    """The live board's full-ink surface is an exception, not a second palette.

    `.ink` exists because the board is a display for a wall or a screen share and stays dark in
    both schemes (#206's recorded exception, carried into the rebuild by #280). Holding it equal
    to the dark block is what stops the exception drifting: a token edited for the dark scheme
    and forgotten here would give the one page nobody looks at closely its own quiet palette.
    """
    css = TOKENS.read_text(encoding="utf-8")
    found = re.search(r"\.ink\s*\{([^}]*)\}", css)
    assert found, "the token file declares no .ink block"
    ink = dict(re.findall(r"(--eb-[a-z0-9-]+)\s*:\s*([^;]+);", found.group(1)))
    assert {k: v.strip() for k, v in ink.items()} == blocks()["dark"]
    assert "color-scheme: dark" in found.group(1), "an ink surface asks for the dark form controls"


def restated(selector: str) -> tuple[dict[str, str], str]:
    """The tokens and the whole body of a block that restates one of the two palettes."""
    css = TOKENS.read_text(encoding="utf-8")
    found = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert found, f"the token file declares no {selector} block"
    body = found.group(1)
    return {k: v.strip() for k, v in re.findall(r"(--eb-[a-z0-9-]+)\s*:\s*([^;]+);", body)}, body


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_a_forced_scheme_restates_its_palette_exactly(scheme):
    """System, Light and Dark: the two forced blocks are the two palettes by another name.

    A person who chooses Light or Dark gets it as `data-eb-scheme` on the root element, which
    the server writes into the document from a cookie: the console may carry no inline script
    and the plain frame paints before the bundle runs, so a choice applied any later would
    flash the wrong scheme. CSS cannot alias a set of custom properties, so each forced block
    restates one of the two above — and holding them equal here is what stops a token edited
    for the system scheme and forgotten in the forced one giving the people who chose a scheme
    a quietly different palette. The dark block declares every colour and the shadow, which is
    exactly the set a forced block carries; the fonts do not change with the scheme and stay
    where they are declared once.
    """
    tokens, body = restated(f':root[data-eb-scheme="{scheme}"]')
    expected = {name: blocks()[scheme][name] for name in blocks()["dark"]}
    assert tokens == expected, sorted(set(tokens.items()) ^ set(expected.items()))
    assert f"color-scheme: {scheme}" in body, "a forced scheme asks for that form of controls"


COMMENT = re.compile(r"/\*.*?\*/|(?:^|(?<=\s))//[^\n]*", re.DOTALL)


def code_lines(path: Path) -> list[tuple[int, str]]:
    """The file's lines with comments blanked, keeping line numbers."""
    text = path.read_text(encoding="utf-8")
    stripped = COMMENT.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), text)
    return list(enumerate(stripped.splitlines(), 1))


def test_no_colour_literal_appears_outside_the_token_file():
    files = [
        path
        for path in sorted((CONSOLE / "src").rglob("*"))
        if path.suffix in {".ts", ".tsx", ".css"}
        and not path.name.endswith((".test.tsx", ".test.ts"))
    ]
    files.append(CONSOLE / "public" / "frame.css")
    offenders = [
        f"{path.relative_to(CONSOLE)}:{number}: {line.strip()}"
        for path in files
        for number, line in code_lines(path)
        if LITERAL.search(line)
    ]
    assert offenders == [], "\n".join(offenders)
