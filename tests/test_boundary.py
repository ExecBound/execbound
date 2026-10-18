# SPDX-License-Identifier: AGPL-3.0-only
"""The hosted boundary (#496): nothing outside the three hosted directories
(`src/execbound/hosted/`, `tests/hosted/` and `console/src/hosted/`) imports hosted code — not
an absolute import, not a relative one, and not a bare mention of `execbound.hosted` anywhere in
an exported file's text, since the global constraint is that core never contains that string at
all (so a docstring or a comment naming it counts as much as a live import does).

Every file under TEXT_ROOTS (src, console, deploy, clients, examples, integrations, migrations,
tests, scripts), whatever its extension, plus every root file the self-hosted export carries
(TEXT_FILES, and REPLACED_FILES from their sources under export/public/ where that directory
exists), is scanned as text for the string itself; every `*.py` file among them is also parsed
and its imports resolved, absolute and relative. The hosted service's deployment file (which
the export does not carry), .github, docs, site and docs-site are not scanned by this rule: the
export publishes a subset of docs, which the export's own scrub reads for the module's name.
The self-hosted export runs this test too, where the hosted directories are gone and any import
this missed fails outright.

Two neighbouring checks ride on the same scan. No `*.py` file holds a string constant that is
exactly the plugin's bare name, since naming it to the loader reaches hosted code without the
module's name; and no core test imports a module from tests/hosted/ or tests/internal/ by its
bare name, which pytest's `sys.path` would otherwise let it do.
"""

import ast
import re
from pathlib import Path

import pytest
from test_repository_rules import SKIPPED

ROOT = Path(__file__).resolve().parents[1]
HOSTED = ("src/execbound/hosted/", "tests/hosted/", "console/src/hosted/")
# tests/internal/ tests files the export leaves out (the hosted service's deployment file,
# the docs site, workflow rules) by name; those names are not the import this rule refuses,
# and the directory is never part of the self-hosted export the docstring above describes.
PRIVATE = ("tests/internal/",)
# Every exported path, whatever the file: console and deploy carry no Python, but are shipped.
TEXT_ROOTS = (
    "src",
    "console",
    "deploy",
    "clients",
    "examples",
    "integrations",
    "migrations",
    "tests",
    "scripts",
)
# Exported root files that live outside every root above: every file the export carries at the
# repository's root. A literal, because the list the export is built from is not exported and
# this test runs in the export too; a private test holds the two equal.
TEXT_FILES = (
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    ".gitleaks.toml",
    ".python-version",
    "DEPENDENCIES.md",
    "Dockerfile",
    "LICENSE",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "alembic.ini",
    "compose.yaml",
    "pyproject.toml",
    "uv.lock",
)
# The root files the export writes from `export/public/` in place of this repository's own:
# the public readme, contributing guide, code of conduct, code owners and coding-agent
# instructions. This repository's own readme and agent instructions never leave, so here the
# scan reads each public source under `export/public/`; in the export, where that directory is
# gone, it reads the root file the export wrote. A private test holds this list to the manifest.
REPLACED_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "CODEOWNERS",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "CONTRIBUTOR_AGREEMENT.md",
    "INTERNAL_USE_LICENSE.md",
    "README.md",
    "TRADEMARK.md",
)
# This file names the module it looks for.
SELF = "tests/test_boundary.py"
# console's git-ignored build output, copied under src/; SKIPPED's "dist" does not match this
# directory's own name.
CONSOLE_DIST = "src/execbound/surfaces/console_dist/"
# The whole-text half of the check: a mention need not be a working import to be forbidden.
TEXT_PATTERN = re.compile(r"\bexecbound\.hosted\b")
# The plugin's bare name. Core never acts on a string that is exactly this word: it is how a
# plugin is named to the loader and read back from it, so it would reach hosted code without
# ever spelling `execbound.hosted`.
PLUGIN_NAME = "hosted"
# pytest puts each test directory on `sys.path` (tests are not packages), so a core test could
# import a hosted or private test module by its bare name. These are those names, read from the
# files themselves; in the self-hosted export the directories are gone and the set is empty.
PRIVATE_TEST_DIRECTORIES = ("tests/hosted", "tests/internal")
PRIVATE_TEST_MODULES = frozenset(
    path.stem for directory in PRIVATE_TEST_DIRECTORIES for path in (ROOT / directory).rglob("*.py")
) - {"__init__", "conftest"}


def _names(tree: ast.AST, relative: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                found.update(_relative_targets(relative, node))
            elif node.module is not None:
                found.add(node.module)
                if node.module == "execbound":
                    found.update("execbound." + alias.name for alias in node.names)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.add(node.value)
    return found


def _relative_targets(relative: str, node: ast.ImportFrom) -> set[str]:
    """What a relative `ast.ImportFrom` in a file under src/execbound/ resolves to, absolute.

    `from .hosted import x` in src/execbound/foo.py, or `from . import hosted` there, each
    resolve to execbound.hosted the same way Python itself resolves the dots: against the
    file's own containing package, walked up once per level beyond the first.
    """
    if not relative.startswith("src/execbound/"):
        return set()
    parts = relative.removeprefix("src/").removesuffix(".py").split("/")
    package = ".".join(parts[:-1]).rsplit(".", node.level - 1)[0]
    if node.module:
        return {f"{package}.{node.module}"}
    return {f"{package}.{alias.name}" for alias in node.names}


def _hosted(name: str) -> bool:
    return name == "execbound.hosted" or name.startswith("execbound.hosted.")


def _names_the_plugin(tree: ast.AST) -> bool:
    """Whether any string constant in the file is exactly the plugin's bare name."""
    return any(
        isinstance(node, ast.Constant) and node.value == PLUGIN_NAME for node in ast.walk(tree)
    )


def _imports_private_test(tree: ast.AST) -> bool:
    """Whether the file imports, by its bare name, a module that lives in a hosted or private
    test directory."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            modules = [node.module]
        else:
            continue
        if any(module.split(".")[0] in PRIVATE_TEST_MODULES for module in modules):
            return True
    return False


def _offends(text: str, relative: str) -> bool:
    """Whether a file's text is what the whole rule refuses: the string itself, an import
    (absolute or relative) that reaches it once the AST is resolved, a string constant that is
    exactly the plugin's name, or, in a core test, an import of a hosted or private test
    module."""
    if TEXT_PATTERN.search(text):
        return True
    if relative.endswith(".py"):
        tree = ast.parse(text, filename=relative)
        if any(_hosted(name) for name in _names(tree, relative)):
            return True
        if _names_the_plugin(tree):
            return True
        if relative.startswith("tests/") and _imports_private_test(tree):
            return True
    return False


def _excluded(path: Path) -> bool:
    rel_path = path.relative_to(ROOT)
    relative = rel_path.as_posix()
    return (
        relative.startswith(HOSTED)
        or relative.startswith(PRIVATE)
        or relative == SELF
        or relative.startswith(CONSOLE_DIST)
        or bool(SKIPPED & set(rel_path.parts))
    )


def _replaced(name: str) -> Path:
    """The text a replaced root file leaves as: its source under `export/public/` where that
    directory exists, as it does here, and the root file itself in the export, where it does
    not. A source missing from an existing `export/public/` is not read from the root, which
    here is this repository's own private file."""
    public = ROOT / "export" / "public"
    return public / name if public.is_dir() else ROOT / name


@pytest.mark.docs
def test_nothing_outside_the_hosted_directories_imports_hosted_code():
    offenders = []
    paths = [ROOT / name for name in TEXT_FILES] + [_replaced(name) for name in REPLACED_FILES]
    for top in TEXT_ROOTS:
        base = ROOT / top
        if base.is_dir():
            paths.extend(path for path in base.rglob("*") if path.is_file())
    for path in sorted(paths):
        if _excluded(path):
            continue
        relative = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if _offends(text, relative):
            offenders.append(relative)
    assert offenders == []


# Several cases trip more than one of _offends's checks (an absolute import is caught by the
# text regex and by the AST names alike), so this is not one case per check. What the cases
# guarantee is that each check has at least one case nothing else catches: the docstring and
# the comment, the text regex alone; `from execbound import hosted`, the AST names alone; the
# implicitly joined literal, the string constants among those names alone; the two relative
# imports, the relative-import resolution alone; and `'hosted'`, the plugin-name check alone.
# Removing any one of those checks turns at least one of these red. The private-test-module
# check has its own cases below, because the names it looks for exist only while the
# directories holding them do, and this table must hold in the self-hosted export too.
POSITIVE = (
    ("from execbound.hosted.signups import submit", "src/execbound/x.py"),
    ("import execbound.hosted", "src/execbound/x.py"),
    ("from execbound import hosted", "src/execbound/x.py"),
    ("importlib.import_module('execbound.hosted.signups')", "src/execbound/x.py"),
    ("x = 'execbound.' 'hosted'", "src/execbound/x.py"),
    ('"""Uses execbound.hosted.signups for uploads."""\n', "src/execbound/x.py"),
    ("# see execbound.hosted for the real implementation\n", "src/execbound/x.py"),
    ("from .hosted import signups", "src/execbound/x.py"),
    ("from .. import hosted", "src/execbound/sub/__init__.py"),
    ("plugins = load_plugins({'hosted': {}})", "src/execbound/x.py"),
)

NEGATIVE = (
    ("execbound.hosted_x", "src/execbound/x.py"),
    ("execbound.hostedness", "src/execbound/x.py"),
    # Resolves to execbound.sub.hosted, a different, unremarkable module.
    ("from . import hosted", "src/execbound/sub/x.py"),
    # The word inside a longer string is not the plugin's name.
    ("x = 'self-hosted'", "src/execbound/x.py"),
    # A core test importing another core test module, as the suite does throughout.
    ("from test_execution import targets", "tests/test_x.py"),
)


def test_the_private_test_modules_are_read_from_the_directories():
    """The import check has names to look for, while the directories exist to hold them."""
    if (ROOT / "tests/hosted").is_dir():
        assert {"hosted_fixtures", "test_hosted_parity"} <= PRIVATE_TEST_MODULES
    if (ROOT / "tests/internal").is_dir():
        assert {"test_docs_site", "test_demo_driver", "test_gate_trial"} <= PRIVATE_TEST_MODULES


def test_the_check_catches_a_core_test_importing_a_private_test_module():
    """Every hosted or private test module, imported by a core test either way. Nothing to
    catch in the self-hosted export, where the modules are gone and such an import fails."""
    for name in sorted(PRIVATE_TEST_MODULES):
        assert _offends(f"import {name}\n", "tests/test_x.py"), name
        assert _offends(f"from {name} import anything\n", "tests/test_x.py"), name
        assert _offends(f"import {name}.part\n", "tests/plugins/x.py"), name


@pytest.mark.parametrize("source,relative", POSITIVE)
def test_the_check_catches_a_hosted_reference(source, relative):
    assert _offends(source, relative), (source, relative)


@pytest.mark.parametrize("source,relative", NEGATIVE)
def test_the_check_lets_a_look_alike_through(source, relative):
    assert not _offends(source, relative), (source, relative)
