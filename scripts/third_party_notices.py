# SPDX-License-Identifier: AGPL-3.0-only
"""Write `THIRD_PARTY_NOTICES.md`, or check that the committed one is current.

    uv run python scripts/third_party_notices.py --console-licenses <file>
    uv run python scripts/third_party_notices.py --console-licenses <file> --check

`<file>` is the output of `pnpm licenses list --prod --json`, run in `console/` after an
install, because the console's license files are only on disk once its packages are.

The notices reproduce what the licenses of the software ExecBound redistributes require: the
license texts and copyright notices of every third-party component a release ships (#122;
#496). Three sources, each read from the copy that ships rather than from a registry:

- **Python:** every third-party distribution a release installs, walked from `uv.lock` by
  `python_sbom.runtime`, with the license files its installed metadata carries. A distribution
  a Linux release does not install, because of a platform marker, is named and not reproduced.
- **Rust:** the crates compiled into `cedarpy`, from the CycloneDX SBOM its wheel bundles
  (PEP 770). The SBOM records each crate's license and author, not the texts, so the standard
  SPDX text of each license it names is reproduced once, from `scripts/licence-texts/`.
- **The console:** the production dependencies the build bundles into the JavaScript the wheel
  and the image serve, with the license files in each package, and the fonts it ships.

The output carries no path, time or machine detail, so the same lockfiles always produce the
same file and `--check` can hold it the way `DEPENDENCIES.md` is held.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "THIRD_PARTY_NOTICES.md"
TEXTS = ROOT / "scripts" / "licence-texts"
LOCKFILE = ROOT / "uv.lock"
DEPENDENCIES = ROOT / "DEPENDENCIES.md"
FONTS = ROOT / "console" / "public" / "fonts" / "LICENSE.txt"
SOURCE = "https://github.com/psycopg/psycopg/tree/{version}"

# A file whose name says it is a license, a notice or an author list, with any suffix.
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|notice|authors)([-_. ].*)?$", re.IGNORECASE)
# SPDX expression operators and parentheses; everything else in an expression is an identifier.
OPERATORS = re.compile(r"\(|\)|\s+(?:AND|OR|WITH)\s+")

_spec = importlib.util.spec_from_file_location("python_sbom", ROOT / "scripts" / "python_sbom.py")
assert _spec is not None and _spec.loader is not None
python_sbom = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("python_sbom", python_sbom)
_spec.loader.exec_module(python_sbom)


class NoticesError(ValueError):
    """A source the notices need is missing or says something they cannot reproduce."""


@dataclass
class Component:
    name: str
    version: str
    licence: str
    texts: list[tuple[str, str]] = field(default_factory=list)  # (label, normalized text)
    note: str = ""


def normalize(text: str) -> str:
    """Line endings, trailing spaces and blank edges only; the words are never touched."""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def fence(text: str) -> str:
    """A `text` block whose fence is longer than any run of backticks the text contains.

    Labelled `text` so Ruff, which formats unlabelled and `python` blocks in Markdown, leaves
    a license alone.
    """
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}text\n{text}{ticks}\n"


def identifiers(expression: str) -> list[str]:
    """The license and exception identifiers an SPDX expression names, in order, once each."""
    found: list[str] = []
    for token in OPERATORS.split(expression):
        token = token.strip()
        if token and token not in found:
            found.append(token)
    return found


def reference(identifier: str) -> str:
    path = TEXTS / f"{identifier}.txt"
    if not path.is_file():
        raise NoticesError(
            f"no reference text for {identifier}: add scripts/licence-texts/{identifier}.txt "
            "from the SPDX License List Data and record its digest in that directory's README"
        )
    return normalize(path.read_text(encoding="utf-8"))


def first_party() -> set[str]:
    document = python_sbom.sections(DEPENDENCIES)
    return set(python_sbom.named(document.get(python_sbom.FIRST_PARTY, [])))


def recorded_licences() -> dict[str, str]:
    """Each distribution's license as `DEPENDENCIES.md` records it, for one not installed."""
    document = python_sbom.sections(DEPENDENCIES)
    table = python_sbom.table(document.get(python_sbom.TABLE, []))
    return {name: licence for name, (licence, _why) in table.items()}


def python_components(lock: dict[str, Any]) -> tuple[list[Component], list[Component]]:
    """(installed, not installed): the third-party distributions a release names."""
    ours = first_party()
    recorded = recorded_licences()
    installed: list[Component] = []
    absent: list[Component] = []
    for name, entry in sorted(python_sbom.runtime(lock).items()):
        if name in ours:
            continue
        version = str(entry.get("version", ""))
        try:
            distribution = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            absent.append(Component(name, version, recorded.get(name, "not recorded")))
            continue
        licence = python_sbom.declared(name) or recorded.get(name, "not declared")
        component = Component(name, distribution.version, licence)
        for item in sorted(distribution.files or [], key=str):
            parts = Path(str(item)).parts
            if not parts or not parts[0].endswith(".dist-info"):
                continue
            inside = len(parts) >= 3 and parts[1] == "licenses"
            top = len(parts) == 2 and LICENCE_FILE.match(parts[1])
            if inside or top:
                text = Path(str(distribution.locate_file(item))).read_text(
                    encoding="utf-8", errors="replace"
                )
                component.texts.append(("/".join(parts[1:]), normalize(text)))
        if not component.texts:
            raise NoticesError(f"{name} {distribution.version} ships no license file")
        installed.append(component)
    return installed, absent


def cedarpy_sbom() -> tuple[str, dict[str, Any]]:
    distribution = metadata.distribution("cedarpy")
    for item in distribution.files or []:
        parts = Path(str(item)).parts
        if len(parts) == 3 and parts[1] == "sboms" and parts[2].endswith(".json"):
            path = Path(str(distribution.locate_file(item)))
            return distribution.version, json.loads(path.read_text(encoding="utf-8"))
    raise NoticesError("cedarpy's wheel bundles no SBOM; its Rust crates cannot be listed")


def rust_components(sbom: dict[str, Any]) -> tuple[list[Component], list[str]]:
    """(crates, identifiers): every crate the SBOM names and every license they use."""
    crates: list[Component] = []
    used: list[str] = []
    for item in sbom.get("components", []):
        expressions = []
        for entry in item.get("licenses", []):
            if "expression" in entry:
                expressions.append(" ".join(str(entry["expression"]).split()))
            elif "license" in entry:
                expressions.append(str(entry["license"].get("id") or entry["license"].get("name")))
        if not expressions:
            raise NoticesError(f"crate {item.get('name')} records no license")
        expression = " AND ".join(f"({e})" if len(expressions) > 1 else e for e in expressions)
        for identifier in identifiers(expression):
            if identifier not in used:
                used.append(identifier)
        author = " ".join(str(item.get("author", "")).split())
        crates.append(
            Component(str(item["name"]), str(item.get("version", "")), expression, note=author)
        )
    crates.sort(key=lambda c: (c.name, c.version))
    return crates, sorted(used)


def console_components(listing: dict[str, Any]) -> list[Component]:
    """Each production package and version, with the license files found in its directory."""
    components: list[Component] = []
    for licence, packages in listing.items():
        for package in packages:
            for version, path in zip(
                package.get("versions", []), package.get("paths", []), strict=False
            ):
                directory = Path(path)
                component = Component(str(package["name"]), str(version), str(licence))
                if directory.is_dir():
                    for file in sorted(directory.iterdir()):
                        if file.is_file() and LICENCE_FILE.match(file.name):
                            text = file.read_text(encoding="utf-8", errors="replace")
                            component.texts.append((file.name, normalize(text)))
                if not component.texts:
                    author = str(package.get("author") or "").strip()
                    component.note = (
                        f"No license file ships with this package; its package.json declares "
                        f"{licence}" + (f" and names {author}" if author else "") + "."
                    )
                    for identifier in identifiers(str(licence)):
                        component.texts.append((f"{identifier} (SPDX text)", reference(identifier)))
                components.append(component)
    components.sort(key=lambda c: (c.name, c.version))
    return components


def _texts(component: Component, seen: dict[str, str], label: str) -> list[str]:
    out: list[str] = []
    for name, text in component.texts:
        digest = hashlib.sha256(text.encode()).hexdigest()
        if digest in seen:
            out.append(f"`{name}`: the same text as {seen[digest]}.\n")
        else:
            seen[digest] = f"{label} `{name}`"
            out.append(f"`{name}`:\n\n{fence(text)}")
    return out


def psycopg_section(installed: list[Component]) -> str:
    versions = {c.name: c.version for c in installed}
    version = versions.get("psycopg")
    if version is None:
        return ""
    native = []
    try:
        binary = metadata.distribution("psycopg-binary")
        native = sorted(
            {Path(str(f)).name.split("-")[0] for f in binary.files or [] if ".libs/" in str(f)}
        )
    except metadata.PackageNotFoundError:
        pass
    lines = [
        "## psycopg and the LGPL\n",
        f"`psycopg` and `psycopg-binary` {version} are licensed under the GNU Lesser General "
        "Public License version 3 only. ExecBound imports them unmodified, as separately "
        "installed Python packages that a user may replace with any compatible build. Their "
        f"complete source code is at <{SOURCE.format(version=version)}>.\n",
    ]
    if native:
        listed = ", ".join(f"`{name}`" for name in native)
        lines.append(
            f"`psycopg-binary` also bundles {len(native)} native libraries: {listed}. Its wheel "
            "ships only its own license, not theirs, so their texts are not reproduced here. "
            "They come from the PostgreSQL client library's own build; building `psycopg` "
            "against a system `libpq` instead would carry the operating system's copies.\n"
        )
    return "\n".join(lines)


def render(
    installed: list[Component],
    absent: list[Component],
    cedarpy: tuple[str, list[Component], list[str]],
    console: list[Component],
) -> str:
    seen: dict[str, str] = {}
    cedarpy_version, crates, used = cedarpy
    parts = [
        "# Third-party notices\n",
        "The license texts and copyright notices of the third-party software an ExecBound "
        "release ships. Generated by `scripts/third_party_notices.py`; do not edit by hand. "
        "ExecBound's own licenses are in `LICENSE` and in the `LICENSE` file of each directory "
        "licensed differently, and `DEPENDENCIES.md` explains why each Python distribution is "
        "here.\n",
    ]
    note = psycopg_section(installed)
    if note:
        parts.append(note)
    parts.append("## Python distributions\n")
    parts.append(
        "Every third-party distribution a release installs, with the license files its "
        "installed metadata carries.\n"
    )
    for c in installed:
        parts.append(f"### {c.name} {c.version}\n\nLicense: {c.licence}\n")
        parts.extend(_texts(c, seen, c.name))
    if absent:
        parts.append("### Not installed by a Linux release\n")
        parts.append(
            "Named by the lockfile for another platform, so a Linux release does not ship them "
            "and their texts are not reproduced.\n"
        )
        parts.append("\n".join(f"- `{c.name}` {c.version}: {c.licence}" for c in absent) + "\n")
    parts.append(f"## Rust crates compiled into cedarpy {cedarpy_version}\n")
    parts.append(
        "From the CycloneDX SBOM that `cedarpy`'s wheel bundles. The SBOM records each crate's "
        "license and author, and the author stands for its copyright holder here; the standard "
        "SPDX text of each license it names follows the table.\n"
    )
    rows = ["| Crate | Version | License | Author |", "| --- | --- | --- | --- |"]
    for c in crates:
        author = c.note.replace("|", "\\|") or "not recorded"
        rows.append(f"| {c.name} | {c.version} | {c.licence} | {author} |")
    parts.append("\n".join(rows) + "\n")
    for identifier in used:
        parts.append(f"### {identifier}\n")
        parts.append(fence(reference(identifier)))
    parts.append("## Console production dependencies\n")
    parts.append(
        "The packages the console's build bundles into the JavaScript the gateway serves, with "
        "the license files found in each.\n"
    )
    for c in console:
        parts.append(f"### {c.name} {c.version}\n\nLicense: {c.licence}\n")
        if c.note:
            parts.append(c.note + "\n")
        parts.extend(_texts(c, seen, f"{c.name} {c.version}"))
    parts.append("## Console fonts\n")
    parts.append(
        "IBM Plex Sans and IBM Plex Mono, Latin-1 subsets, under the SIL Open Font License 1.1.\n"
    )
    parts.append(fence(normalize(FONTS.read_text(encoding="utf-8"))))
    return "\n".join(parts)


def build(console_listing: Path) -> str:
    installed, absent = python_components(python_sbom.load_lock(LOCKFILE))
    version, sbom = cedarpy_sbom()
    crates, used = rust_components(sbom)
    listing = json.loads(console_listing.read_text(encoding="utf-8"))
    return render(installed, absent, (version, crates, used), console_components(listing))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--console-licenses", type=Path, required=True, help="pnpm licenses list --prod --json"
    )
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    try:
        text = build(args.console_licenses)
    except NoticesError as error:
        print(f"third_party_notices: {error}", file=sys.stderr)
        return 2
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != text:
            print(
                f"{args.output.name} is not current; run scripts/third_party_notices.py "
                "--console-licenses <pnpm licenses list --prod --json> and commit the result",
                file=sys.stderr,
            )
            return 1
        print(f"{args.output.name} is current")
        return 0
    args.output.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {args.output.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
