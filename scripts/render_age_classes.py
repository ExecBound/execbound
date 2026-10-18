# SPDX-License-Identifier: AGPL-3.0-only
"""Write the board's age classes into `app.css` between its markers.

A shot is anchored on its own event time by a negative `animation-delay`, so a reload
lands every shot within a tenth of a second of where it was. That needs one class per
tenth of a second of motion, and 151 rules is more than anyone should keep in step by
hand — but it still has to be in the stylesheet that ships, because the Content Security
Policy forbids inline style and nothing may be generated at request time.

So it is generated here and checked by a test that re-runs this and compares. Run it after
changing `MAX_AGE_TENTHS`.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STYLESHEET = ROOT / "src" / "execbound" / "surfaces" / "assets" / "app.css"
BEGIN = "/* BEGIN generated age classes - scripts/render_age_classes.py */"
END = "/* END generated age classes */"
MAX_AGE_TENTHS = 150


def block() -> str:
    rules = "\n".join(
        f".age-{tenths} {{ animation-delay: -{tenths / 10:.1f}s; }}"
        for tenths in range(MAX_AGE_TENTHS + 1)
    )
    return f"{BEGIN}\n{rules}\n{END}"


def render(stylesheet: Path = STYLESHEET) -> str:
    css = stylesheet.read_text(encoding="utf-8")
    start, finish = css.find(BEGIN), css.find(END)
    if start < 0 or finish < start:
        raise SystemExit("The stylesheet carries no generated age class markers.")
    return css[:start] + block() + css[finish + len(END) :]


def main() -> int:
    rendered = render()
    if rendered == STYLESHEET.read_text(encoding="utf-8"):
        print("Age classes are current.")
        return 0
    STYLESHEET.write_text(rendered, encoding="utf-8")
    print(f"Age classes rendered: {MAX_AGE_TENTHS + 1} rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
