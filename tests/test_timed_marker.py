# SPDX-License-Identifier: AGPL-3.0-only
"""Every test that takes the machine's timing lock is `timed`, and no other test is (#747).

A run that selects `-m "not timed"` leaves these tests out; the full suite includes them. The
marker and the lock are held to each other both ways. A test that asks for `timed_alone` without
the marker would put the lock's waits back into a run that deselects `timed`; a `timed` test that
takes no lock would be left out of that run for no reason. A fixture never asks for the lock,
which would make its tests timed without saying so. And no `timed` test is evidence the
validation gate checks: a run that selects `not timed` leaves it out, so gate evidence must never
be timed.
"""

import ast
from pathlib import Path

from execbound_harness.validation_evidence import ACCEPTANCE_PREFIXES

TESTS = Path(__file__).parent
ROOT = TESTS.parent


def _is_timed(node: ast.expr) -> bool:
    """`pytest.mark.timed`, written bare or called."""
    if isinstance(node, ast.Call):
        node = node.func
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "timed"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "mark"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "pytest"
    )


def _module_is_timed(tree: ast.Module) -> bool:
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "pytestmark"
            for target in statement.targets
        ):
            value = statement.value
            marks = value.elts if isinstance(value, ast.List | ast.Tuple) else [value]
            if any(_is_timed(mark) for mark in marks):
                return True
    return False


def _arguments(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = function.args.posonlyargs + function.args.args + function.args.kwonlyargs
    return {argument.arg for argument in arguments}


def _scan() -> tuple[set[str], set[str], list[str]]:
    """The tests that take the lock, the tests marked `timed`, and any other function that
    asks for the lock, each as a node id or a location."""
    takes_lock: set[str] = set()
    timed: set[str] = set()
    others: list[str] = []
    for path in sorted(TESTS.rglob("*.py")):
        if path.name == "conftest.py":
            continue
        relative = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module_timed = _module_is_timed(tree)
        scopes: list[tuple[str, list[ast.stmt]]] = [("", tree.body)]
        scopes += [
            (f"::{node.name}", node.body) for node in tree.body if isinstance(node, ast.ClassDef)
        ]
        for prefix, body in scopes:
            for node in body:
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if not node.name.startswith("test_"):
                    if "timed_alone" in _arguments(node):
                        others.append(f"{relative}:{node.lineno} {node.name}")
                    continue
                node_id = f"{relative}{prefix}::{node.name}"
                if "timed_alone" in _arguments(node):
                    takes_lock.add(node_id)
                if module_timed or any(_is_timed(mark) for mark in node.decorator_list):
                    timed.add(node_id)
    return takes_lock, timed, others


def test_every_test_that_takes_the_timing_lock_is_timed_and_no_other_test_is():
    takes_lock, timed, _ = _scan()
    assert takes_lock, "no test asks for `timed_alone`: was the fixture renamed?"
    assert sorted(timed - takes_lock) == [], "timed without taking the lock"
    assert sorted(takes_lock - timed) == [], "takes the lock without being timed"


def test_only_a_test_asks_for_the_timing_lock():
    assert _scan()[2] == []


def test_no_timed_test_is_evidence_the_validation_gate_checks():
    prefixes = tuple(prefix for group in ACCEPTANCE_PREFIXES.values() for prefix in group)
    assert sorted(node for node in _scan()[1] if node.startswith(prefixes)) == []
