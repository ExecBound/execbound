# SPDX-License-Identifier: AGPL-3.0-only
"""A test that reads a document carries the `docs` marker, which this plugin holds true (#748).

`pytest -m docs` selects the tests whose result a change to documents alone can change, which
is what a documentation-only check runs. Which tests those are is not kept by hand. This plugin
installs one audit hook (`sys.addaudithook`) and notes every document a test opens, by
`tests/document_paths.py`'s rule, and every listing of a directory that holds documents,
wherever it happens:

- in the test's setup, call or teardown, which is the test's own read;
- in a fixture's setup, which also makes every later test that uses that same fixture
  definition a reader, since a fixture scoped wider than one test is set up once and reused;
- in a module's top-level code while it is imported, inside a test or before any, which makes
  that module a reader, and with it every test module that imports it, however far down.

A test that reads a document by any of these ways and does not carry `docs`, on itself, its
class or its module, fails at teardown naming what it read. Two things are not seen: a read in
another process (a script the test runs, the formatter, an export build), which is checked by a
step or job of its own, and a check that only asks whether a document exists (`exists()` and
`stat()` raise no audit event), which a test must mark by hand.
"""

import ast
import functools
import os
import sys
from collections.abc import Generator
from pathlib import Path
from types import FrameType, ModuleType
from typing import Any

import pytest
from document_paths import is_document

ROOT = Path(__file__).resolve().parents[1]
MARKER = "docs"
# Directories whose listing is a read of the documents in them.
DOCUMENT_DIRECTORIES = ("docs", "export/public")

# What is running now, set by the hooks below and read by the audit hook.
_item: pytest.Item | None = None
_fixtures: list[tuple[str, str]] = []
_reads: dict[str, set[str]] = {}  # an item's node id, to what its run read
_fixture_reads: dict[tuple[str, str], set[str]] = {}  # a fixture definition, to what it read
_module_reads: dict[str, set[str]] = {}  # a module file, to what its import read


def _relative(path: object) -> str | None:
    """A path relative to the repository's root, written with `/`, or None."""
    if not isinstance(path, str | bytes | os.PathLike):
        return None
    absolute = Path(os.fsdecode(os.fspath(path)))
    try:
        if not absolute.is_absolute():
            absolute = Path.cwd() / absolute
        return absolute.resolve().relative_to(ROOT).as_posix()
    except (OSError, ValueError):
        return None


def _document(event: str, path: object) -> str | None:
    """What an `open` or a directory listing read, relative to the root, or None."""
    if event == "open":
        if not isinstance(path, str | bytes | os.PathLike):
            return None
        # Every file the suite opens passes through here; anything not Markdown leaves at once.
        if not os.fsdecode(os.fspath(path)).endswith(".md"):
            return None
        relative = _relative(path)
        return relative if relative is not None and is_document(relative) else None
    relative = _relative(path)
    if relative is None:
        return None
    for directory in DOCUMENT_DIRECTORIES:
        if relative == directory or relative.startswith(directory + "/"):
            return relative + "/"
    return None


def _library_code(name: str) -> bool:
    """Whether a file is the interpreter's own or an installed package's code."""
    library = tuple(
        str(Path(prefix).resolve()) + os.sep for prefix in {sys.prefix, sys.base_prefix}
    )
    return name.startswith("<") or name.startswith(library) or "site-packages" in name


def _importing(frame: FrameType | None) -> set[str]:
    """The files whose top-level code is running on the stack, other than this plugin and the
    interpreter's own or an installed package's: the modules being imported."""
    found = set()
    while frame is not None:
        name = frame.f_code.co_filename
        if frame.f_code.co_name == "<module>" and name != __file__ and not _library_code(name):
            found.add(name)
        frame = frame.f_back
    return found


def _audit(event: str, arguments: tuple[object, ...]) -> None:
    if event not in ("open", "os.listdir", "os.scandir") or not arguments:
        return
    document = _document(event, arguments[0])
    if document is None:
        return
    for module in _importing(sys._getframe(1)):
        _module_reads.setdefault(module, set()).add(document)
    if _item is not None:
        _reads.setdefault(_item.nodeid, set()).add(document)
        for fixture in _fixtures:
            _fixture_reads.setdefault(fixture, set()).add(document)


def pytest_configure(config: pytest.Config) -> None:
    if not getattr(sys, "_execbound_document_audit", False):
        sys.addaudithook(_audit)
        sys._execbound_document_audit = True  # type: ignore[attr-defined]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, object]:
    global _item
    _item = item
    try:
        yield
    finally:
        _item = None
        _fixtures.clear()


def _fixture_key(fixturedef: Any) -> tuple[str, str]:
    """A fixture definition, by where it is defined and its name: two fixtures of one name in
    different modules are different fixtures."""
    return (str(getattr(fixturedef, "baseid", "")), str(fixturedef.argname))


@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(
    fixturedef: pytest.FixtureDef[object], request: pytest.FixtureRequest
) -> Generator[None, object]:
    _fixtures.append(_fixture_key(fixturedef))
    try:
        yield
    finally:
        _fixtures.pop()


@functools.cache
def _imported_names(file: str) -> tuple[str, ...]:
    """The module names a source file imports, absolute imports only."""
    try:
        tree = ast.parse(Path(file).read_text(encoding="utf-8"), filename=file)
    except (OSError, SyntaxError, UnicodeDecodeError):
        return ()
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
            names += [f"{node.module}.{alias.name}" for alias in node.names]
    return tuple(names)


def _imports(file: str) -> list[str]:
    """The files of the modules a source file imports that are loaded now, read afresh each
    time, since a module may first be imported inside a test."""
    found = []
    for name in _imported_names(file):
        source = getattr(sys.modules.get(name), "__file__", None)
        if isinstance(source, str) and not _library_code(source):
            found.append(source)
    return found


def _imported_readers(module: ModuleType) -> set[str]:
    """What the module and every module it imports, however far down, read while imported."""
    start = getattr(module, "__file__", None)
    if not isinstance(start, str):
        return set()
    found: set[str] = set()
    seen = {start}
    frontier = [start]
    while frontier:
        file = frontier.pop()
        found |= _module_reads.get(file, set())
        for imported in _imports(file):
            if imported not in seen:
                seen.add(imported)
                frontier.append(imported)
    return found


def documents_read(item: pytest.Item) -> set[str]:
    """Everything `item`'s result can depend on, by the ways the module docstring names."""
    documents = set(_reads.get(item.nodeid, set()))
    definitions = getattr(getattr(item, "_fixtureinfo", None), "name2fixturedefs", {})
    for name in getattr(item, "fixturenames", ()):
        for fixturedef in definitions.get(name, ()):
            documents |= _fixture_reads.get(_fixture_key(fixturedef), set())
    module = getattr(item, "module", None)
    if isinstance(module, ModuleType):
        documents |= _imported_readers(module)
    return documents


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, Any]:
    outcome = yield
    report: pytest.TestReport = outcome.get_result()
    if report.when != "teardown" or item.get_closest_marker(MARKER) is not None:
        return
    documents = documents_read(item)
    if documents and report.outcome != "failed":
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} reads {', '.join(sorted(documents))} without "
            f"@pytest.mark.{MARKER}: mark the test, or its module with "
            f"`pytestmark = pytest.mark.{MARKER}`, so `pytest -m {MARKER}` selects it "
            "(tests/document_reads.py)."
        )
