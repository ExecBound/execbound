# SPDX-License-Identifier: AGPL-3.0-only
"""`THIRD_PARTY_NOTICES.md` reproduces what a release ships, and nothing about the machine.

`scripts/third_party_notices.py` reads the license files of the Python distributions a
release installs, the Rust crates `cedarpy`'s bundled SBOM names and the console's production
packages. The console's half needs its packages installed, so `verify` checks the whole file
after the console build. These cases need no install: they plant each input the real tree does
not have, and hold the committed file's Python and Rust sections, which render before the
console's and never depend on it, to a regeneration from the installed environment.
"""

import importlib.metadata as metadata
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "third_party_notices", ROOT / "scripts" / "third_party_notices.py"
)
assert _spec is not None and _spec.loader is not None
notices = importlib.util.module_from_spec(_spec)
sys.modules["third_party_notices"] = notices
_spec.loader.exec_module(notices)

CONSOLE = "## Console production dependencies\n"


def test_normalizing_touches_line_endings_and_edges_but_never_the_words():
    raw = "\n\n  Copyright (c) Someone  \r\nPermission is granted.\t\r\n\r\n\n"
    assert notices.normalize(raw) == "  Copyright (c) Someone\nPermission is granted.\n"


def test_a_fence_outlasts_any_backticks_in_the_text_and_is_labelled_text():
    assert notices.fence("plain\n") == "```text\nplain\n```\n"
    fenced = notices.fence("a ```` run\n")
    assert fenced.startswith("`````text\n") and fenced.endswith("`````\n")


@pytest.mark.parametrize(
    ("expression", "found"),
    [
        ("MIT", ["MIT"]),
        ("MIT OR Apache-2.0", ["MIT", "Apache-2.0"]),
        ("(MIT OR Apache-2.0) AND Unicode-3.0", ["MIT", "Apache-2.0", "Unicode-3.0"]),
        ("Apache-2.0 WITH LLVM-exception", ["Apache-2.0", "LLVM-exception"]),
        ("Apache-2.0 OR MIT OR Apache-2.0", ["Apache-2.0", "MIT"]),
    ],
)
def test_an_expression_names_its_licences_and_exceptions_once_each(expression, found):
    assert notices.identifiers(expression) == found


def test_a_licence_with_no_canonical_text_is_refused_by_name():
    with pytest.raises(notices.NoticesError, match="no reference text for Made-Up-1.0"):
        notices.reference("Made-Up-1.0")


def test_each_crate_the_sbom_names_becomes_a_row_and_its_licences_are_collected():
    sbom = {
        "components": [
            {
                "name": "zeta",
                "version": "2.0",
                "author": "Z  Author",
                "licenses": [{"expression": "Apache-2.0  OR  MIT"}],
            },
            {"name": "alpha", "version": "1.0", "licenses": [{"license": {"id": "Zlib"}}]},
        ]
    }
    crates, used = notices.rust_components(sbom)
    assert [(c.name, c.licence, c.note) for c in crates] == [
        ("alpha", "Zlib", ""),
        ("zeta", "Apache-2.0 OR MIT", "Z Author"),
    ]
    assert used == ["Apache-2.0", "MIT", "Zlib"]


def test_a_crate_that_records_no_licence_is_refused():
    with pytest.raises(notices.NoticesError, match="crate bare records no license"):
        notices.rust_components({"components": [{"name": "bare", "version": "1"}]})


def test_the_console_listing_reads_each_packages_files_and_falls_back_to_the_spdx_text(tmp_path):
    shipped = tmp_path / "has-licence"
    shipped.mkdir()
    (shipped / "LICENSE.md").write_text("Copyright (c) Shipped\r\nMIT terms.\r\n")
    (shipped / "index.js").write_text("")
    bare = tmp_path / "no-licence"
    bare.mkdir()
    listing = {
        "MIT": [
            {"name": "shipped", "versions": ["1.0"], "paths": [str(shipped)], "author": "S"},
            {"name": "bare", "versions": ["2.0"], "paths": [str(bare)], "author": "B Author"},
        ]
    }
    shipped_c, bare_c = sorted(
        notices.console_components(listing), key=lambda c: c.name != "shipped"
    )
    assert shipped_c.texts == [("LICENSE.md", "Copyright (c) Shipped\nMIT terms.\n")]
    assert bare_c.note == (
        "No license file ships with this package; its package.json declares MIT and names B Author."
    )
    assert bare_c.texts == [("MIT (SPDX text)", notices.reference("MIT"))]
    rendered = notices.render([], [], ("0", [], []), [shipped_c, bare_c])
    assert str(tmp_path) not in rendered, "a machine path reached the notices"


def test_an_identical_text_is_reproduced_once_and_pointed_to_after():
    first = notices.Component("one", "1", "MIT", texts=[("LICENSE", "same words\n")])
    second = notices.Component("two", "1", "MIT", texts=[("LICENSE", "same words\n")])
    rendered = notices.render([], [], ("0", [], []), [first, second])
    assert rendered.count("same words") == 1
    assert "`LICENSE`: the same text as one 1 `LICENSE`." in rendered


@pytest.mark.docs
def test_every_third_party_distribution_a_release_installs_is_reproduced():
    installed, absent = notices.python_components(notices.python_sbom.load_lock(notices.LOCKFILE))
    names = {c.name for c in installed}
    assert names.isdisjoint(notices.first_party()), (
        "ExecBound's own distributions are not third-party"
    )
    assert "cedarpy" in names and "psycopg" in names
    assert all(c.texts for c in installed), "an installed distribution reproduced no license"
    for component in absent:
        with pytest.raises(metadata.PackageNotFoundError):
            metadata.distribution(component.name)
        assert component.licence != "not recorded", f"{component.name} is not in DEPENDENCIES.md"


@pytest.mark.docs
def test_the_committed_python_and_rust_sections_are_what_the_environment_ships():
    """The half that needs no console install, held on every run of the suite."""
    installed, absent = notices.python_components(notices.python_sbom.load_lock(notices.LOCKFILE))
    version, sbom = notices.cedarpy_sbom()
    crates, used = notices.rust_components(sbom)
    fresh = notices.render(installed, absent, (version, crates, used), [])
    committed = notices.OUTPUT.read_text(encoding="utf-8")
    assert CONSOLE in fresh and CONSOLE in committed
    assert committed.split(CONSOLE)[0] == fresh.split(CONSOLE)[0], (
        "THIRD_PARTY_NOTICES.md is not current; run scripts/third_party_notices.py"
    )


@pytest.mark.docs
def test_the_lgpl_note_points_at_the_installed_psycopgs_own_source():
    installed, _ = notices.python_components(notices.python_sbom.load_lock(notices.LOCKFILE))
    note = notices.psycopg_section(installed)
    version = metadata.version("psycopg")
    assert f"<https://github.com/psycopg/psycopg/tree/{version}>" in note
    assert "GNU Lesser General Public License version 3 only" in note


@pytest.mark.docs
def test_check_passes_a_current_file_and_fails_a_stale_one(tmp_path, capsys):
    listing = tmp_path / "console.json"
    listing.write_text(json.dumps({}))
    output = tmp_path / "NOTICES.md"
    args = ["--console-licenses", str(listing), "--output", str(output)]
    assert notices.main(args) == 0
    assert notices.main([*args, "--check"]) == 0
    output.write_text(output.read_text() + "\nedited by hand\n")
    assert notices.main([*args, "--check"]) == 1
    assert "is not current" in capsys.readouterr().err
