# SPDX-License-Identifier: AGPL-3.0-only
"""The generated part of the stylesheet, and the rules the board's markup has to keep.

The age classes ship in the stylesheet because the Content Security Policy forbids inline
style and nothing may be generated at request time, so they are generated at author time
and checked here. `board.html` itself is not part of the core package (#496), and its
no-inline-style, no-SMIL markup check is not a core test.
"""

import re
from pathlib import Path

from execbound.surfaces.board import MAX_AGE_TENTHS

ROOT = Path(__file__).resolve().parents[1]
STYLESHEET = ROOT / "src" / "execbound" / "surfaces" / "assets" / "app.css"


def generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "render_age_classes", ROOT / "scripts" / "render_age_classes.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_stylesheet_carries_exactly_what_the_generator_writes():
    """Re-run the generator and compare its output with the committed stylesheet.

    A stylesheet edited by hand inside the markers would drift from the generator and the
    next person to run it would produce a diff nobody asked for.
    """
    assert generator().render() == STYLESHEET.read_text(encoding="utf-8")


def test_the_generator_is_idempotent():
    module = generator()
    once = module.render()
    assert module.render(STYLESHEET) == once


def test_every_age_the_board_can_produce_has_a_class():
    """`_age` clamps to MAX_AGE_TENTHS, so the classes must cover zero through it.

    A shot whose class does not exist would animate from the start of its phase rather
    than from where it actually is, which is a picture that quietly lies about time.
    """
    css = STYLESHEET.read_text(encoding="utf-8")
    for tenths in (0, 1, MAX_AGE_TENTHS // 2, MAX_AGE_TENTHS):
        assert f".age-{tenths} {{" in css
    assert f".age-{MAX_AGE_TENTHS + 1} {{" not in css


def test_the_board_stylesheet_uses_tokens_and_not_colours():
    css = STYLESHEET.read_text(encoding="utf-8")
    # From the first board rule, not from the section comment: slicing into a comment
    # leaves it unterminated and its own issue reference reads as a colour.
    board = css[css.find(".board-page") :]
    uncommented = re.sub(r"/\*.*?\*/", "", board, flags=re.DOTALL)
    assert re.findall(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(", uncommented) == []


def test_the_phases_the_stylesheet_animates_are_the_phases_the_board_assigns():
    """A phase with no rule is a shot drawn at the origin and never moved.

    The mapping in `board.PHASES` is the only place a phase is invented, so the stylesheet
    has to answer every one of them.
    """
    from execbound.surfaces.board import PHASES

    css = STYLESHEET.read_text(encoding="utf-8")
    for phase, _ in PHASES.values():
        assert f".shot.{phase}" in css, phase
    # The two phases the read adds that no state maps to.
    for phase in ("short",):
        assert f".shot.{phase}" in css, phase
