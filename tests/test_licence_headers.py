# SPDX-License-Identifier: AGPL-3.0-only
"""Every file names its license as the map gives it (#496).

`scripts/licence_headers.py` holds the map from directory to license, the comment syntax of
each file type and the files that take the map without a line. These cases run it over small
trees they write under `tmp_path`, with `git init` where git's listing is the point. The
script is public, so this file runs in the self-hosted export too.
"""

import ast
import importlib.util
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "licence_headers.py"

_spec = importlib.util.spec_from_file_location("licence_headers", SCRIPT)
assert _spec is not None and _spec.loader is not None
licence_headers = importlib.util.module_from_spec(_spec)
sys.modules["licence_headers"] = licence_headers
_spec.loader.exec_module(licence_headers)

TAG = "SPDX-License-Identifier"
AGPL = "AGPL-3.0-only"
APACHE = "Apache-2.0"
PROPRIETARY = "LicenseRef-ExecBound-Proprietary"


def tree(root: Path, files: dict[str, str | bytes]) -> Path:
    """Write `files` under `root`, each path relative to it, and return `root`."""
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8", newline="")
    return root


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True)


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("src/execbound/policy.py", f"# {TAG}: {AGPL}"),
        ("scripts/tool.sh", f"# {TAG}: {AGPL}"),
        ("compose.yaml", f"# {TAG}: {AGPL}"),
        (".github/workflows/ci.yml", f"# {TAG}: {AGPL}"),
        ("pyproject.toml", f"# {TAG}: {AGPL}"),
        ("alembic.ini", f"# {TAG}: {AGPL}"),
        ("tests/sdk-examples.in", f"# {TAG}: {AGPL}"),
        ("console/public/robots.txt", f"# {TAG}: {AGPL}"),
        ("Dockerfile", f"# {TAG}: {AGPL}"),
        ("CODEOWNERS", f"# {TAG}: {AGPL}"),
        (".gitignore", f"# {TAG}: {AGPL}"),
        (".gitattributes", f"# {TAG}: {AGPL}"),
        (".dockerignore", f"# {TAG}: {AGPL}"),
        ("console/.npmrc", f"# {TAG}: {AGPL}"),
        (".env.example", f"# {TAG}: {AGPL}"),
        (".python-version", f"# {TAG}: {AGPL}"),
        ("migrations/script.py.mako", f"# {TAG}: {AGPL}"),
        ("console/src/main.tsx", f"// {TAG}: {AGPL}"),
        ("console/src/lib/words.ts", f"// {TAG}: {AGPL}"),
        ("console/eslint.config.js", f"// {TAG}: {AGPL}"),
        ("console/scripts/budget.mjs", f"// {TAG}: {AGPL}"),
        ("console/src/styles/app.css", f"/* {TAG}: {AGPL} */"),
        ("console/index.html", f"<!-- {TAG}: {AGPL} -->"),
        ("console/src/assets/logo.svg", f"<!-- {TAG}: {AGPL} -->"),
        ("docs-site/static/sitemap.xml", f"<!-- {TAG}: {AGPL} -->"),
        ("src/execbound/surfaces/templates/base.html", f"{{#- {TAG}: {AGPL} -#}}"),
        ("src/execbound/surfaces/templates/recipes/demo.sh", f"{{#- {TAG}: {APACHE} -#}}"),
        ("src/execbound/surfaces/templates/recipes/cursor.json", f"{{#- {TAG}: {APACHE} -#}}"),
    ],
)
def test_each_syntax_writes_its_own_line_first(tmp_path, path, line):
    assert licence_headers.header_line(path) == line
    root = tree(tmp_path, {path: "body\n"})
    assert licence_headers.problems(root, [path]) == [
        f"{path}:1: no {TAG} line; it must read {line!r}"
    ]
    assert licence_headers.write(root, [path]) == [path]
    assert (root / path).read_text(encoding="utf-8") == f"{line}\nbody\n"
    assert licence_headers.problems(root, [path]) == []


@pytest.mark.parametrize(
    "path",
    [
        "docs/GUIDE.md",
        "README.md",
        "docs/api/agent-v1.json",
        "compliance/tracking/controls.csv",
        "console/public/fonts/Plex.woff2",
        "console/public/favicon.ico",
        "console/public/apple-touch-icon.png",
        "docs-site/static/img/console-home.webp",
        "clients/python/src/execbound_client/py.typed",
    ],
)
def test_markdown_json_csv_and_binary_files_take_the_map_without_a_line(tmp_path, path):
    assert not licence_headers.is_exempt(path), "the type decides here, not the exemptions"
    assert licence_headers.syntax_for(path) is None
    assert licence_headers.header_line(path) is None
    root = tree(tmp_path, {path: b"\x89PNG\r\n\x1a\n\x00\xff" if path.endswith(".png") else "x\n"})
    before = (root / path).read_bytes()
    assert licence_headers.problems(root, [path]) == []
    assert licence_headers.write(root, [path]) == []
    assert (root / path).read_bytes() == before


def test_an_empty_file_takes_the_map_without_a_line(tmp_path):
    root = tree(tmp_path, {"src/execbound/surfaces/__init__.py": ""})
    assert licence_headers.problems(root, ["src/execbound/surfaces/__init__.py"]) == []
    assert licence_headers.write(root, ["src/execbound/surfaces/__init__.py"]) == []
    assert (root / "src/execbound/surfaces/__init__.py").read_bytes() == b""


def test_a_type_with_no_decision_is_named_rather_than_guessed(tmp_path):
    root = tree(tmp_path, {"tools/notes.adoc": "= Notes\n"})
    with pytest.raises(licence_headers.UnknownType):
        licence_headers.syntax_for("tools/notes.adoc")
    [problem] = licence_headers.problems(root, ["tools/notes.adoc"])
    assert problem.startswith("tools/notes.adoc: no comment syntax is recorded for 'notes.adoc'")
    assert licence_headers.write(root, ["tools/notes.adoc"]) == []


def test_a_shebang_stays_first_and_the_line_goes_second(tmp_path):
    root = tree(
        tmp_path,
        {
            "scripts/ci.py": '#!/usr/bin/env python3\n"""CI."""\n',
            "console/scripts/budget.mjs": "#!/usr/bin/env node\nconsole.log(1);\n",
            "scripts/bare.sh": "#!/bin/sh",
        },
    )
    assert sorted(licence_headers.write(root, licence_headers.tracked(root))) == [
        "console/scripts/budget.mjs",
        "scripts/bare.sh",
        "scripts/ci.py",
    ]
    assert (root / "scripts/ci.py").read_text() == (
        f'#!/usr/bin/env python3\n# {TAG}: {AGPL}\n"""CI."""\n'
    )
    assert (root / "console/scripts/budget.mjs").read_text() == (
        f"#!/usr/bin/env node\n// {TAG}: {AGPL}\nconsole.log(1);\n"
    )
    assert (root / "scripts/bare.sh").read_text() == f"#!/bin/sh\n# {TAG}: {AGPL}"
    assert licence_headers.problems(root, licence_headers.tracked(root)) == []
    assert licence_headers.expected_position(["#!/bin/sh", "x"]) == 1
    assert licence_headers.expected_position(["#!/bin/sh", "x"], "scripts/bare.sh") == 1
    assert licence_headers.expected_position(["x", "#!/bin/sh"]) == 0
    assert licence_headers.expected_position([]) == 0


def test_an_xml_declaration_stays_first_and_the_line_goes_second(tmp_path):
    declaration = '<?xml version="1.0" encoding="UTF-8"?>'
    path = "docs-site/static/sitemap.xml"
    root = tree(tmp_path, {path: f"{declaration}\n<urlset/>\n"})
    [problem] = licence_headers.problems(root, [path])
    assert problem.startswith(f"{path}:2: no {TAG} line")
    assert licence_headers.write(root, [path]) == [path]
    assert (root / path).read_text() == f"{declaration}\n<!-- {TAG}: {AGPL} -->\n<urlset/>\n"


@pytest.mark.parametrize("first", ["#!/bin/sh", '<?xml version="1.0" encoding="UTF-8"?>'])
def test_a_jinja_template_takes_its_line_first_and_renders_as_before(tmp_path, first):
    """`{#-` strips the line break before it, so a line put second, after `#!` or `<?xml`,
    would join the first line to the third. A template's line goes first whatever it opens
    with, and renders as nothing. The recipes' own environment renders it."""
    from execbound.surfaces.recipes import _templates as recipes

    path = "src/execbound/surfaces/templates/recipes/bootstrap.sh"
    source = f"{first}\nset -eu\n  curl {{{{ origin }}}}/health\n"
    root = tree(tmp_path, {path: source})
    before = recipes.from_string(source).render(origin="https://gateway.example")
    assert before == f"{first}\nset -eu\n  curl https://gateway.example/health\n"

    assert licence_headers.expected_position(source.split("\n"), path) == 0
    [problem] = licence_headers.problems(root, [path])
    assert problem.startswith(f"{path}:1: no {TAG} line")
    assert licence_headers.write(root, [path]) == [path]
    written = (root / path).read_text()
    assert written == f"{{#- {TAG}: {APACHE} -#}}\n{source}"
    assert licence_headers.problems(root, [path]) == []
    assert recipes.from_string(written).render(origin="https://gateway.example") == before


@pytest.mark.parametrize(
    "path",
    [
        "migrations/versions/0001_foundation.py",
        "migrations/versions/0059_step.py",
        "migrations/versions/0067_step_up_window.py",
        "tests/fixtures/recipes/demo.sh",
        "tests/fixtures/endpoint-contract-v1.json",
        "scripts/licence-texts/MIT.txt",
        "LICENSE",
        "examples/LICENSE",
        "console/public/fonts/LICENSE.txt",
        "uv.lock",
        "console/pnpm-lock.yaml",
        "docs-site/pnpm-lock.yaml",
        "tests/sdk-examples.txt",
        "tests/mcp-legacy.txt",
        "src/execbound/hosted/data/disposable_domains.txt",
        "site/index.html",
        "site/robots.txt",
        "site/sitemap.xml",
        "site/.well-known/security.txt",
        "site/favicon.svg",
        "site/styles.css",
        "console/public/favicon.svg",
    ],
)
def test_an_exempt_file_takes_the_map_and_write_leaves_it_alone(tmp_path, path):
    assert licence_headers.is_exempt(path)
    assert licence_headers.syntax_for(path) is None
    root = tree(tmp_path, {path: "pinned bytes\n"})
    assert licence_headers.problems(root, [path]) == []
    assert licence_headers.write(root, [path]) == []
    assert (root / path).read_text() == "pinned bytes\n"


def test_only_a_licence_file_among_the_exempt_may_carry_a_line_and_only_the_right_one(tmp_path):
    """A license file opens with its own identifier. Every other exempt file takes no line at
    all: the website is served as committed and an applied migration is never edited, so a
    line added to either by hand is named, even the one the map would give."""
    root = tree(
        tmp_path,
        {
            "examples/LICENSE": f"Copyright 2026 ExecBound LLC\n{TAG}: {APACHE}\n\ntext\n",
            "docs/LICENSE": f"Copyright 2026 ExecBound LLC\n{TAG}: {AGPL}\n\ntext\n",
            "site/index.html": f"<!-- {TAG}: {PROPRIETARY} -->\n<!doctype html>\n",
            "migrations/versions/0067_step_up_window.py": f'# {TAG}: {AGPL}\n"""Applied."""\n',
            "tests/fixtures/recipes/demo.sh": f"echo 1\necho 2\n# {TAG}: {APACHE}\n",
        },
    )
    paths = licence_headers.tracked(root)
    before = {path: (root / path).read_bytes() for path in paths}
    exempt = f"this file is exempt and takes no {TAG} line; remove it"
    assert licence_headers.problems(root, paths) == [
        "docs/LICENSE:2: the line must name CC-BY-4.0, as the map does",
        f"migrations/versions/0067_step_up_window.py:1: {exempt}",
        f"site/index.html:1: {exempt}",
        f"tests/fixtures/recipes/demo.sh:3: {exempt}",
    ]
    assert licence_headers.write(root, paths) == []
    assert {path: (root / path).read_bytes() for path in paths} == before


def test_only_the_applied_migrations_are_exempt_and_a_new_one_needs_its_line(tmp_path):
    """Revisions up to 0067 are applied and never edited. A new one takes its line from the
    Alembic template or from `--write`, so a hand-written revision without it is named."""
    applied = "migrations/versions/0067_step_up_window.py"
    new = "migrations/versions/0068_security_signals.py"
    root = tree(
        tmp_path,
        {
            "migrations/versions/0001_foundation.py": '"""Applied."""\n',
            applied: '"""Applied."""\n',
            new: '"""New."""\n',
        },
    )
    assert licence_headers.is_exempt(applied)
    assert not licence_headers.is_exempt(new)
    assert not licence_headers.is_exempt("migrations/versions/0100_later.py")
    paths = licence_headers.tracked(root)
    assert licence_headers.problems(root, paths) == [
        f"{new}:1: no {TAG} line; it must read '# {TAG}: {AGPL}'"
    ]
    assert licence_headers.write(root, paths) == [new]
    assert (root / new).read_text() == f'# {TAG}: {AGPL}\n"""New."""\n'
    assert (root / applied).read_text() == '"""Applied."""\n'
    assert licence_headers.problems(root, paths) == []


def test_a_byte_order_mark_is_named_and_write_leaves_the_file_alone(tmp_path):
    """A line written before the mark would leave the mark inside the file: Python refuses the
    module, and an `<?xml` declaration no longer opens it. A person removes the mark first. A
    file that takes the map, as a CSV does, may keep one."""
    files = {
        "src/execbound/marked.py": '\ufeff"""Marked."""\n',
        "console/public/marked.xml": '\ufeff<?xml version="1.0"?>\n<urlset/>\n',
        "compliance/tracking/controls.csv": "\ufeffid,name\n",
    }
    root = tree(tmp_path, files)
    paths = sorted(files)
    before = {path: (root / path).read_bytes() for path in paths}
    assert licence_headers.problems(root, paths) == [
        "console/public/marked.xml: starts with a byte-order mark; remove it",
        "src/execbound/marked.py: starts with a byte-order mark; remove it",
    ]
    assert licence_headers.write(root, paths) == []
    assert {path: (root / path).read_bytes() for path in paths} == before


def test_a_symlink_is_never_followed_and_a_path_out_of_the_tree_is_refused(tmp_path):
    """Git records a link as a link, and its target is checked under its own path. Following
    one would rewrite a file anywhere the link points, outside the tree included."""
    victim = tmp_path / "outside" / "victim.py"
    victim.parent.mkdir()
    victim.write_text("x = 1\n")
    root = tree(tmp_path / "root", {"src/execbound/real.py": "x = 1\n"})
    (root / "src/execbound/link.py").symlink_to("../../../outside/victim.py")
    (root / "linked").symlink_to("../outside", target_is_directory=True)
    git(root, "init", "-q")
    git(root, "add", ".")
    paths = licence_headers.tracked(root)
    assert paths == ["linked", "src/execbound/link.py", "src/execbound/real.py"]
    assert licence_headers.problems(root, paths) == [
        f"src/execbound/real.py:1: no {TAG} line; it must read '# {TAG}: {AGPL}'"
    ]
    assert licence_headers.write(root, paths) == ["src/execbound/real.py"]
    assert licence_headers.problems(root, paths) == []
    for given in ("src/execbound/link.py", "linked/victim.py"):
        assert licence_headers.main(["--root", str(root), "--write", given]) == 2, given
    assert victim.read_bytes() == b"x = 1\n"


def test_a_symlinked_parent_directory_is_never_followed_either(tmp_path):
    """Git tracks `pkg/a.py`, and `pkg` is then a link on disk to a directory outside the
    tree. Git's index and the working tree disagree, and the file git names is not at its own
    path, so neither mode reads or writes through the link."""
    victim = tmp_path / "outside" / "a.py"
    victim.parent.mkdir()
    victim.write_text("x = 1\n")
    root = tree(tmp_path / "root", {"pkg/a.py": "x = 1\n", "src/execbound/real.py": "x = 1\n"})
    git(root, "init", "-q")
    git(root, "add", ".")
    for file in (root / "pkg").iterdir():
        file.unlink()
    (root / "pkg").rmdir()
    (root / "pkg").symlink_to("../outside", target_is_directory=True)
    paths = licence_headers.tracked(root)
    assert paths == ["pkg/a.py", "src/execbound/real.py"]
    assert licence_headers.problems(root, paths) == [
        f"src/execbound/real.py:1: no {TAG} line; it must read '# {TAG}: {AGPL}'"
    ]
    assert licence_headers.write(root, paths) == ["src/execbound/real.py"]
    assert licence_headers.main(["--root", str(root), "--write"]) == 0
    assert licence_headers.main(["--root", str(root)]) == 0
    assert victim.read_bytes() == b"x = 1\n"


def test_a_wrong_identifier_or_syntax_is_named_and_write_corrects_it(tmp_path):
    root = tree(
        tmp_path,
        {
            "examples/plain_http.py": f"# {TAG}: {AGPL}\nimport os\n",
            "console/src/main.tsx": f"# {TAG}: {AGPL}\nexport {{}};\n",
        },
    )
    paths = ["console/src/main.tsx", "examples/plain_http.py"]
    assert licence_headers.problems(root, paths) == [
        f"console/src/main.tsx:1: a wrong {TAG} line; it must read '// {TAG}: {AGPL}'",
        f"examples/plain_http.py:1: a wrong {TAG} line; it must read '# {TAG}: {APACHE}'",
    ]
    assert licence_headers.write(root, paths) == paths
    assert (root / "examples/plain_http.py").read_text() == f"# {TAG}: {APACHE}\nimport os\n"
    assert (root / "console/src/main.tsx").read_text() == f"// {TAG}: {AGPL}\nexport {{}};\n"
    assert licence_headers.problems(root, paths) == []


def test_a_second_line_anywhere_is_a_problem_that_write_leaves_for_a_person(tmp_path):
    text = f'# {TAG}: {AGPL}\n"""Module."""\n\n    # {TAG}: {APACHE}\nx = 1\n'
    root = tree(tmp_path, {"src/execbound/stray.py": text})
    expected = [f"src/execbound/stray.py:4: a second {TAG} line; the file's one line is its line 1"]
    assert licence_headers.problems(root, ["src/execbound/stray.py"]) == expected
    assert licence_headers.write(root, ["src/execbound/stray.py"]) == []
    assert licence_headers.problems(root, ["src/execbound/stray.py"]) == expected


def test_code_that_quotes_the_tag_is_not_a_line(tmp_path):
    text = f'# {TAG}: {AGPL}\nLINE = "# {TAG}: {AGPL}"\nheader = f"{{x}}\\n{TAG}: {{y}}"\n'
    root = tree(tmp_path, {"tests/test_quoting.py": text})
    assert licence_headers.problems(root, ["tests/test_quoting.py"]) == []


def test_a_file_that_takes_the_map_may_not_open_with_a_line(tmp_path):
    root = tree(tmp_path, {"docs/GUIDE.md": f"<!-- {TAG}: CC-BY-4.0 -->\n# Guide\n"})
    assert licence_headers.problems(root, ["docs/GUIDE.md"]) == [
        "docs/GUIDE.md:1: this type takes the map without a line; remove it"
    ]
    assert licence_headers.write(root, ["docs/GUIDE.md"]) == []


def test_write_is_idempotent_and_keeps_the_mode_and_the_line_endings(tmp_path):
    root = tree(
        tmp_path,
        {
            "src/execbound/a.py": '"""A."""\n',
            "src/execbound/data/community/initdb/01-runtime-role.sh": "#!/bin/sh\nset -eu\n",
            "console/src/b.ts": "export const b = 1;\r\nexport const c = 2;\r\n",
            "src/execbound/surfaces/templates/page.html": '{% extends "base.html" %}\n',
            "docs/GUIDE.md": "# Guide\n",
        },
    )
    script = root / "src/execbound/data/community/initdb/01-runtime-role.sh"
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    paths = licence_headers.tracked(root)
    assert licence_headers.write(root, paths) == [
        "console/src/b.ts",
        "src/execbound/a.py",
        "src/execbound/data/community/initdb/01-runtime-role.sh",
        "src/execbound/surfaces/templates/page.html",
    ]
    after = {path: (root / path).read_bytes() for path in paths}
    assert licence_headers.write(root, paths) == []
    assert {path: (root / path).read_bytes() for path in paths} == after
    assert licence_headers.problems(root, paths) == []
    assert script.stat().st_mode & stat.S_IXUSR
    assert script.read_text() == f"#!/bin/sh\n# {TAG}: {APACHE}\nset -eu\n"
    assert (root / "console/src/b.ts").read_bytes() == (
        f"// {TAG}: {AGPL}\r\nexport const b = 1;\r\nexport const c = 2;\r\n".encode()
    )


@pytest.mark.parametrize(
    ("path", "licence"),
    [
        ("export/public/README.md", AGPL),
        ("export/public/.github/workflows/ci.yml", AGPL),
        ("export/public/CODE_OF_CONDUCT.md", "CC-BY-4.0"),
        ("export/public/examples/extra.py", APACHE),
        ("export/public/docs/EXTRA.md", "CC-BY-4.0"),
        ("export/manifest.json", AGPL),
    ],
)
def test_an_export_replacement_takes_its_destinations_licence(path, licence):
    assert licence_headers.licence_for(path) == licence


def test_the_replacement_rule_reaches_the_syntax_and_the_exemptions_too():
    assert licence_headers.header_line("export/public/CODEOWNERS") == f"# {TAG}: {AGPL}"
    assert licence_headers.header_line("export/public/.github/ISSUE_TEMPLATE/bug.yml") == (
        f"# {TAG}: {AGPL}"
    )
    assert licence_headers.is_exempt("export/public/LICENSE")
    assert not licence_headers.is_exempt("export/public/README.md")


@pytest.mark.parametrize(
    ("path", "licence"),
    [
        ("pyproject.toml", AGPL),
        ("src/execbound/app.py", AGPL),
        ("src/execbound/hostedness.py", AGPL),
        ("src/execbound/hosted/pages.py", PROPRIETARY),
        ("src/execbound/data/community/compose.yaml", APACHE),
        ("src/execbound/data/starters/packs.json", APACHE),
        ("src/execbound/data/policy.json", AGPL),
        ("src/execbound/surfaces/templates/recipes/demo.sh", APACHE),
        ("src/execbound/surfaces/templates/base.html", AGPL),
        ("clients/python/src/execbound_client/sync.py", APACHE),
        ("protocol/src/execbound_protocol/catalog.py", APACHE),
        ("protocol/pyproject.toml", APACHE),
        ("connectors/src/execbound_connectors/mock_app.py", APACHE),
        ("clients/other/x.py", AGPL),
        ("examples/mcp_agent.py", APACHE),
        ("integrations/tines/tines_gate_story.py", APACHE),
        ("deploy/community/README.md", APACHE),
        ("docs/GUIDE.md", "CC-BY-4.0"),
        ("docs-site/prepare.mjs", AGPL),
        ("console/src/main.tsx", AGPL),
        ("console/index.html", AGPL),
        ("console/src/hosted/edition.tsx", PROPRIETARY),
        ("console/public/fonts/Plex.woff2", "OFL-1.1"),
        ("site/fonts/LICENSE.txt", "OFL-1.1"),
        ("site/index.html", PROPRIETARY),
        ("site/.well-known/security.txt", PROPRIETARY),
        ("tests/test_policy.py", AGPL),
        ("tests/hosted/test_signups.py", PROPRIETARY),
    ],
)
def test_the_longest_prefix_wins(path, licence):
    assert licence_headers.licence_for(path) == licence


def test_a_file_licence_names_one_path_exactly():
    assert licence_headers.FILE_LICENCES == {"CODE_OF_CONDUCT.md": "CC-BY-4.0"}
    assert licence_headers.licence_for("CODE_OF_CONDUCT.md") == "CC-BY-4.0"
    assert licence_headers.licence_for("examples/CODE_OF_CONDUCT.md") == APACHE
    assert licence_headers.licence_for("CODE_OF_CONDUCT.txt") == AGPL


def test_git_lists_what_it_tracks_and_a_tree_without_git_is_walked(tmp_path):
    files = {
        ".gitignore": "\n".join(
            [
                ".venv/",
                "__pycache__/",
                "*.py[cod]",
                ".env",
                ".env.*",
                "!.env.example",
                "console/src/api/",
            ]
        ),
        ".env": "SECRET=1\n",
        ".env.example": "SECRET=\n",
        ".env.local": "SECRET=2\n",
        ".github/workflows/ci.yml": "name: CI\n",
        ".venv/lib/site.py": "x = 1\n",
        "src/execbound/__pycache__/app.cpython-313.pyc": b"\x00",
        "src/execbound/app.py": "x = 1\n",
        "console/src/api/client.gen.ts": "export {};\n",
        "console/src/main.tsx": "export {};\n",
        "docs-site/static/.well-known/security.txt": "Contact: mailto:security@example.org\n",
    }
    kept = [
        ".env.example",
        ".github/workflows/ci.yml",
        ".gitignore",
        "console/src/main.tsx",
        "docs-site/static/.well-known/security.txt",
        "src/execbound/app.py",
    ]
    walked = tree(tmp_path / "walked", files)
    assert licence_headers.tracked(walked) == kept

    listed = tree(tmp_path / "listed", files)
    git(listed, "init", "-q")
    assert licence_headers.tracked(listed) == kept, "a repository that tracks nothing is walked"
    git(listed, "add", ".gitignore", "src/execbound/app.py")
    assert licence_headers.tracked(listed) == [".gitignore", "src/execbound/app.py"]


def test_a_pattern_that_ends_in_a_slash_ignores_a_directory_but_not_a_file_of_that_name(
    tmp_path,
):
    root = tree(
        tmp_path,
        {
            ".gitignore": "build/\n",
            "build/out.js": "x\n",
            "console/build/out.js": "x\n",
            "scripts/build": "#!/bin/sh\n",
        },
    )
    assert licence_headers.tracked(root) == [".gitignore", "scripts/build"]


def test_the_root_gitignore_holds_only_patterns_the_walk_models():
    """Where there is no `.git`, the walk reads the root `.gitignore` with `fnmatch`, which is
    not git's matcher: its `*`, `?` and `[...]` cross `/`, and it knows neither `**` nor a
    backslash escape. A pattern that needs any of them would make the walk read other files
    than `git ls-files` lists, so the exported tree would be checked over a different set from
    its commit. Write the pattern another way, or teach `_ignored` git's rules first."""
    for raw in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern = line.removeprefix("!").rstrip("/")
        assert "**" not in pattern, f"the walk does not model `**`: {line}"
        assert "\\" not in pattern, f"the walk does not model a backslash escape: {line}"
        if "/" in pattern:
            assert not set("*?[") & set(pattern), (
                f"the walk's wildcards cross `/` in a pattern with a slash: {line}"
            )


def test_a_git_that_cannot_list_the_files_is_a_usage_failure_not_a_problem(
    tmp_path, monkeypatch, capsys
):
    """Exit 1 names problems in the files. Git failing to list them, or missing altogether,
    says nothing about the files, so it is exit 2 with one line saying why."""
    root = tree(tmp_path, {".git": "gitdir: missing\n", "src/execbound/a.py": "x = 1\n"})
    assert licence_headers.main(["--root", str(root)]) == 2
    [message] = capsys.readouterr().err.splitlines()
    assert message.startswith(f"licence_headers: git could not list the files under {root}: ")

    monkeypatch.setenv("PATH", str(tmp_path / "no-git-here"))
    assert licence_headers.main(["--root", str(root)]) == 2
    [message] = capsys.readouterr().err.splitlines()
    assert message.startswith(f"licence_headers: git could not list the files under {root}: ")


def test_the_command_line_checks_writes_and_refuses(tmp_path, capsys):
    root = tree(tmp_path / "root", {"src/execbound/a.py": "x = 1\n", "docs/GUIDE.md": "# Guide\n"})
    (tmp_path / "outside.py").write_text("x = 1\n")
    assert licence_headers.main(["--root", str(root)]) == 1
    assert f"src/execbound/a.py:1: no {TAG} line" in capsys.readouterr().err
    assert licence_headers.main(["--root", str(root), "--check", "docs/GUIDE.md"]) == 0
    assert licence_headers.main(["--root", str(root), "--write"]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == (
        "licence_headers: 2 files read, 1 written; every line is right"
    )
    assert licence_headers.main(["--root", str(root), "--check"]) == 0

    (root / "src/execbound/b.py").write_text(f"x = 1\n# {TAG}: {AGPL}\n")
    assert licence_headers.main(["--root", str(root), "--write", "src/execbound/b.py"]) == 1
    assert "src/execbound/b.py:3: a second" in capsys.readouterr().err

    # A path given by hand is read at its own path: one through `..` or a linked directory
    # would take the license of the path as written, not of the file it reaches.
    hosted = tree(root, {"src/execbound/hosted/p.py": "x = 1\n"}) / "src/execbound/hosted/p.py"
    (root / "alias").symlink_to("src/execbound/hosted", target_is_directory=True)
    for usage in (
        ["--check", "--write"],
        ["--root", str(root), "--bogus"],
        ["--root", str(root), "src/execbound/missing.py"],
        ["--root", str(root), "../outside.py"],
        ["--root", str(root), "--write", "src/../src/execbound/hosted/p.py"],
        ["--root", str(root), "--write", "alias/p.py"],
        ["--root", str(root), str(root / "src/execbound/a.py")],
        ["--root", str(root / "docs/GUIDE.md")],
    ):
        assert licence_headers.main(usage) == 2, usage
    assert hosted.read_text() == "x = 1\n"


def test_a_file_that_cannot_be_read_or_written_is_exit_2_not_a_problem(
    tmp_path, monkeypatch, capsys
):
    """Exit 1 names problems in the files. A file the script cannot read or write says
    nothing about its line, so it is exit 2 with one line naming the error."""
    root = tree(tmp_path, {"src/execbound/a.py": "x = 1\n"})

    def unreadable(file: Path) -> str:
        raise PermissionError(13, "Permission denied", str(file))

    monkeypatch.setattr(licence_headers, "_text", unreadable)
    for mode in ("--check", "--write"):
        assert licence_headers.main(["--root", str(root), mode]) == 2, mode
        [message] = capsys.readouterr().err.splitlines()
        assert message == (
            f"licence_headers: [Errno 13] Permission denied: '{root / 'src/execbound/a.py'}'"
        )


def test_the_script_is_standard_library_only_and_parses_under_python_3_12():
    """It runs as `python3` in CI, which is 3.12, outside the locked environment."""
    parsed = ast.parse(SCRIPT.read_text(encoding="utf-8"), feature_version=(3, 12))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(parsed)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(parsed)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported <= sys.stdlib_module_names, imported - sys.stdlib_module_names


@pytest.mark.docs
def test_every_file_in_this_tree_names_the_licence_the_map_gives_it():
    """The map, held over the whole tree: this repository's, or the export's, where the
    hosted directories are absent and nothing else changes. A branch that merged `main`
    without rerunning `--write` fails here, naming each file."""
    found = licence_headers.problems(ROOT, licence_headers.tracked(ROOT))
    fix = "Run `python3 scripts/licence_headers.py --write` and commit what it changes."
    assert found == [], "\n".join([*found[:40], fix])
