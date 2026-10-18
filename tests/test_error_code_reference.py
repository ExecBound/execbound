# SPDX-License-Identifier: AGPL-3.0-only
"""The error and refusal code reference lists exactly the codes each interface answers with.

`docs/ERROR_CODES.md` is written by hand, because what a code means and what to do about it
are not in the code. These tests hold each of its tables to the list the code keeps: every
execution code any module raises, at the status the gateway answers it with; the reasons a
denial records; the causes a refused resolution records, and admission's generic reason for
an unexpected fault; the console API's closed list, at its statuses; and, for each owner
command family and each intake API, every code its error class is raised with in the modules
it runs, at the intake API's status, with the codes a collection run records without raising
one. A code missing from a table fails, and so does a row for a code nothing returns.
"""

import ast
import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

from execbound.monitoring.models import MONITOR_STATUS
from execbound.resolution.registry import RESOLUTION_CODES
from execbound.signals.intake import SIGNAL_STATUS
from execbound.surfaces.agent_api_guide import DECISION_REASONS
from execbound.surfaces.agent_openapi import UNAVAILABLE_CODES
from execbound.surfaces.console_api.errors import CODES as CONSOLE_CODES
from execbound.surfaces.http import ERROR_STATUS

# Reads a document, so it carries `docs` and `pytest -m docs` selects it (#748).
pytestmark = pytest.mark.docs

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "docs" / "ERROR_CODES.md"
SOURCES = ROOT / "src"

# What `ExecutionError()` carries when it is raised with no code.
DEFAULT_CODE = "EXECUTION_UNAVAILABLE"

# The reason admission records for an unexpected database or value error, outside the closed
# list of resolution causes. Every resolution refusal but bad arguments carried it before
# September 28, 2026, so records keep it and the refused-before-admission table lists it.
GENERIC_ADMISSION_REASON = "DEPENDENCY_OR_CONTEXT_UNAVAILABLE"
ADMISSION = SOURCES / "execbound" / "execution" / "admission.py"

# Calls that raise an execution error with a code these tests cannot read, by file and count,
# each with what the code can be. A new one fails until it is reviewed here.
DYNAMIC_SITES = {
    "src/execbound/cli.py": (
        1,
        "tenant-assistant re-raises an AssistantError's code, so the command's refusal path "
        "is the execution commands'; those codes are the assistant's own",
    ),
    "src/execbound/recovery_run.py": (
        2,
        "RecoveryStopped re-raises the execution error that stopped the run, and SweepFailed "
        "carries the first failed sweep's code, from an AssistantError, ExecutionError or "
        "PolicyStoreError",
    ),
}


@dataclass(frozen=True)
class Family:
    """One table of codes: an error class, the modules under `src/execbound` whose raises it
    lists (a file or a package), and, for an HTTP interface, the statuses it answers with,
    every other code being 400."""

    section: str
    error: str
    modules: tuple[str, ...]
    status: Mapping[str, int] | None = None


FAMILIES = (
    Family("Administration", "AdministrationError", ("administration.py", "cli.py")),
    Family("Spaces", "SpaceError", ("spaces.py",)),
    Family("Provisioning", "ProvisioningError", ("provisioning.py", "cli.py")),
    Family(
        "Policy bundles", "PolicyStoreError", ("policy/store.py", "policy/preview.py", "cli.py")
    ),
    Family("Teammate invitations", "InvitationError", ("invitations.py", "cli.py")),
    Family("The assistant", "AssistantError", ("assistant",)),
    Family("Plugins", "PluginError", ("plugins.py",)),
    Family("Restore verification", "RecoveryError", ("recovery.py",)),
    Family("The monitoring API", "MonitorError", ("monitoring",), MONITOR_STATUS),
    Family("The signal intake API", "SignalError", ("signals",), SIGNAL_STATUS),
)

# Raises whose code is another error's, passed through, by file: how many, and the section
# that lists those codes, which the family's own section links to. `None` is a plugin's own
# code, which that plugin documents.
PASSED_THROUGH: dict[str, tuple[int, str | None]] = {
    "src/execbound/administration.py": (2, "Spaces"),
    "src/execbound/assistant/proposals.py": (1, "Policy bundles"),
    "src/execbound/invitations.py": (1, "Teammate invitations"),
    "src/execbound/plugins.py": (1, None),
}

# Codes a command prints itself, as text rather than through an error, and the table each
# belongs to; the modules searched for them are the command modules below.
PRINTED = {
    "COMMAND_CONFLICT": "Plugins",
    "FINDINGS_DESTINATIONS_CONFIGURED": "The monitoring API",
}
COMMAND_MODULES = ("cli.py", "monitoring/commands.py", "recovery.py")

# Codes a collection run records on its connection or reports in its result without raising
# them, the table each belongs to, and the modules that write them.
RECORDED = {"CAPACITY": ("The monitoring API", ("monitoring/store.py",))}

_ROW = re.compile(r"^\| `([A-Z][A-Z0-9_]*(?::<rule id>)?)` \| (.+?) \|(?: .+? \|)?$")


def _sections() -> dict[str, list[str]]:
    """Each `##` or `###` section's lines, by its heading."""
    sections: dict[str, list[str]] = {}
    lines: list[str] = []
    for line in REFERENCE.read_text(encoding="utf-8").splitlines():
        if line.startswith(("## ", "### ")):
            lines = sections.setdefault(line.split(" ", 1)[1], [])
            continue
        lines.append(line)
    return sections


def reference_tables() -> dict[str, dict[str, str]]:
    """Each section's rows: the code in the first cell, and the second cell's text."""
    tables: dict[str, dict[str, str]] = {}
    section = None
    for line in REFERENCE.read_text(encoding="utf-8").splitlines():
        if line.startswith(("## ", "### ")):
            section = line.split(" ", 1)[1]
            tables[section] = {}
            continue
        match = _ROW.match(line)
        if match is None or section is None:
            continue
        code, second = match.groups()
        assert code not in tables[section], f"{section}: {code} has two rows"
        tables[section][code] = second
    return tables


def _execution_error_classes(trees: list[ast.Module]) -> tuple[set[str], dict[str, str]]:
    """`ExecutionError` and its subclasses by name, and the subclasses that fix their code.

    A subclass whose `__init__` passes a literal to `super().__init__` always carries that
    code, so its call sites name no code of their own."""
    classes = {"ExecutionError"}
    fixed: dict[str, str] = {}
    grew = True
    while grew:
        grew = False
        for tree in trees:
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef) or node.name in classes:
                    continue
                if any(isinstance(base, ast.Name) and base.id in classes for base in node.bases):
                    classes.add(node.name)
                    grew = True
                    for call in ast.walk(node):
                        if (
                            isinstance(call, ast.Call)
                            and isinstance(call.func, ast.Attribute)
                            and call.func.attr == "__init__"
                            and call.args
                            and isinstance(call.args[0], ast.Constant)
                        ):
                            fixed[node.name] = call.args[0].value
    return classes, fixed


def raised_execution_codes() -> tuple[set[str], dict[str, int]]:
    """Every code an execution error is raised with, and the count of calls whose code is
    built at run time, by file."""
    paths = sorted(SOURCES.rglob("*.py"))
    trees = {path: ast.parse(path.read_text(encoding="utf-8")) for path in paths}
    classes, fixed = _execution_error_classes(list(trees.values()))
    codes = set(fixed.values())
    dynamic: dict[str, int] = {}
    for path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = function.attr if isinstance(function, ast.Attribute) else None
            name = function.id if isinstance(function, ast.Name) else name
            if name not in classes or name in fixed:
                continue
            if not node.args:
                codes.add(DEFAULT_CODE)
                continue
            argument = node.args[0]
            branches = (
                [argument.body, argument.orelse] if isinstance(argument, ast.IfExp) else [argument]
            )
            if all(isinstance(b, ast.Constant) and isinstance(b.value, str) for b in branches):
                codes.update(b.value for b in branches if isinstance(b, ast.Constant))
            else:
                where = path.relative_to(ROOT).as_posix()
                dynamic[where] = dynamic.get(where, 0) + 1
    return codes, dynamic


def _module_paths(family: Family) -> list[Path]:
    paths: list[Path] = []
    for module in family.modules:
        path = SOURCES / "execbound" / module
        paths.extend(sorted(path.rglob("*.py")) if path.is_dir() else [path])
    return paths


def _enclosing(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.FunctionDef | None:
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.FunctionDef):
            return node
    return None


@dataclass
class _Module:
    name: str
    parents: dict[ast.AST, ast.AST]
    calls: dict[str, list[ast.Call]]


def _resolve(
    expr: ast.expr, function: ast.FunctionDef | None, module: _Module
) -> tuple[set[str], bool]:
    """The codes an expression can be that can be read, and whether that is all of them.

    Read: a literal, and `None` as no code; a conditional of readable branches;
    `x if x in CODES else "FALLBACK"` against the module's own set; `TABLE.get(x, "FALLBACK")`
    against its own table; a parameter of a function in the same module, through what its
    callers pass and, where a call leaves it out, its default; and a local assigned only
    readable values. Anything else is a code passed through from somewhere these tests do not
    read, and so is a parameter a call may pass inside a `*` or `**` it spreads."""
    if isinstance(expr, ast.Constant) and (expr.value is None or isinstance(expr.value, str)):
        return ({expr.value} if expr.value is not None else set()), True
    if isinstance(expr, ast.IfExp):
        test = expr.test
        own = importlib.import_module(module.name)
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and isinstance(test.comparators[0], ast.Name)
            and hasattr(own, test.comparators[0].id)
        ):
            fallback, whole = _resolve(expr.orelse, function, module)
            return set(getattr(own, test.comparators[0].id)) | fallback, whole
        body, body_whole = _resolve(expr.body, function, module)
        orelse, orelse_whole = _resolve(expr.orelse, function, module)
        return body | orelse, body_whole and orelse_whole
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "get"
        and isinstance(expr.func.value, ast.Name)
        and len(expr.args) == 2
    ):
        table = getattr(importlib.import_module(module.name), expr.func.value.id)
        fallback, whole = _resolve(expr.args[1], function, module)
        return set(table.values()) | fallback, whole
    if isinstance(expr, ast.Name) and function is not None:
        signature = function.args
        by_place = [argument.arg for argument in (*signature.posonlyargs, *signature.args)]
        by_name = [argument.arg for argument in (*signature.args, *signature.kwonlyargs)]
        if expr.id in by_place or expr.id in by_name:
            defaults = dict(
                zip(
                    by_place[len(by_place) - len(signature.defaults) :],
                    signature.defaults,
                    strict=True,
                )
            )
            for argument, default in zip(signature.kwonlyargs, signature.kw_defaults, strict=True):
                if default is not None:
                    defaults[argument.arg] = default
            # A method called on its object or class is not passed `self` or `cls` by place.
            bound = isinstance(module.parents.get(function), ast.ClassDef) and not any(
                isinstance(decorator, ast.Name) and decorator.id == "staticmethod"
                for decorator in function.decorator_list
            )
            codes: set[str] = set()
            whole = True
            for call in module.calls.get(function.name, []):
                index = by_place.index(expr.id) if expr.id in by_place else None
                if index is not None and bound and isinstance(call.func, ast.Attribute):
                    index -= 1
                keyword = expr.id if expr.id in by_name else None
                argument, readable = _passed(call, keyword, index)
                if not readable:
                    whole = False
                    continue
                scope = _enclosing(call, module.parents)
                if argument is None:
                    # Left out, so the default, which is read where the function is defined.
                    argument, scope = defaults.get(expr.id), _enclosing(function, module.parents)
                if argument is None:
                    continue
                resolved, complete = _resolve(argument, scope, module)
                codes |= resolved
                whole = whole and complete
            return codes, whole
        assigned = [
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == expr.id for t in node.targets)
        ]
        if assigned:
            codes, whole = set(), True
            for value in assigned:
                resolved, complete = _resolve(value, function, module)
                codes |= resolved
                whole = whole and complete
            return codes, whole
    return set(), False


def _passed(call: ast.Call, keyword: str | None, index: int | None) -> tuple[ast.expr | None, bool]:
    """What a call passes for one parameter, by `keyword` or at place `index`, or `None` where
    it leaves the parameter out; and whether that can be told, which it cannot when the call
    spreads a `*` or `**` that could carry it."""
    for given in call.keywords:
        if keyword is not None and given.arg == keyword:
            return given.value, True
    if index is not None and index >= 0:
        for place, argument in enumerate(call.args):
            if isinstance(argument, ast.Starred):
                return None, False
            if place == index:
                return argument, True
    spread = any(isinstance(argument, ast.Starred) for argument in call.args) or any(
        given.arg is None for given in call.keywords
    )
    return None, not spread


def _default_code(error: ast.ClassDef) -> set[str]:
    """The code the class carries when raised with none: its `code` parameter's default."""
    for method in error.body:
        if isinstance(method, ast.FunctionDef) and method.name == "__init__":
            arguments = method.args.args
            defaults = dict(
                zip(
                    arguments[len(arguments) - len(method.args.defaults) :],
                    method.args.defaults,
                    strict=True,
                )
            )
            for argument, default in defaults.items():
                if argument.arg == "code" and isinstance(default, ast.Constant):
                    return {default.value}
    return set()


def family_codes(family: Family) -> tuple[set[str], dict[str, int]]:
    """Every code the family's class is raised with in its modules, and the count of raises
    whose code is passed through from another error, by file. The class's default code
    counts only where a raise gives none."""
    trees = {path: ast.parse(path.read_text(encoding="utf-8")) for path in _module_paths(family)}
    default: set[str] = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == family.error:
                default = _default_code(node)
    # A subclass defined beside the class carries the same codes, unless it is a family of
    # its own, as `ProvisioningError` is.
    errors = {family.error}
    others = {other.error for other in FAMILIES} - errors
    grew = True
    while grew:
        grew = False
        for tree in trees.values():
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ClassDef)
                    and node.name not in errors | others
                    and any(isinstance(b, ast.Name) and b.id in errors for b in node.bases)
                ):
                    errors.add(node.name)
                    grew = True
    codes: set[str] = set()
    passed: dict[str, int] = {}
    for path, tree in trees.items():
        name = ".".join(path.relative_to(SOURCES).with_suffix("").parts)
        raised, through = _raised(_read(name, tree), errors, default)
        codes |= raised
        if through:
            passed[path.relative_to(ROOT).as_posix()] = through
    return codes, passed


def _read(name: str, tree: ast.Module) -> _Module:
    """A parsed module with each node's parent and every call by the name it calls."""
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    calls: dict[str, list[ast.Call]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = node.func
            called = callee.attr if isinstance(callee, ast.Attribute) else None
            called = callee.id if isinstance(callee, ast.Name) else called
            if called is not None:
                calls.setdefault(called, []).append(node)
    return _Module(name, parents, calls)


def _raised(module: _Module, errors: set[str], default: set[str]) -> tuple[set[str], int]:
    """The codes the module raises any of `errors` with, and how many of those raises pass a
    code through that cannot be read; `default` is what a raise naming no code carries."""
    codes: set[str] = set()
    through = 0
    for call in [call for error in errors for call in module.calls.get(error, [])]:
        given = call.args[:1] or [k.value for k in call.keywords if k.arg == "code"]
        if not given:
            codes |= default
            continue
        resolved, whole = _resolve(given[0], _enclosing(call, module.parents), module)
        codes |= resolved
        through += not whole
    return codes, through


def _same(section: str, expected: set[str]) -> dict[str, str]:
    table = reference_tables()[section]
    assert not expected - set(table), f"{section}, missing: {sorted(expected - set(table))}"
    assert not set(table) - expected, f"{section}, nothing returns: {sorted(set(table) - expected)}"
    return table


def test_the_execution_table_lists_every_execution_code_at_its_status() -> None:
    raised, _ = raised_execution_codes()
    assert len(raised) > 30
    table = _same("Execution codes", raised | set(ERROR_STATUS) | set(UNAVAILABLE_CODES))
    wrong = {
        code: status for code, status in table.items() if status != str(ERROR_STATUS.get(code, 503))
    }
    assert not wrong, f"statuses that differ from the gateway's: {wrong}"


def test_every_execution_code_built_at_run_time_has_been_reviewed() -> None:
    _, dynamic = raised_execution_codes()
    assert dynamic == {path: count for path, (count, _) in DYNAMIC_SITES.items()}


def test_the_denial_table_lists_exactly_the_reasons_a_denial_records() -> None:
    _same("Why a request was denied", {code for code, _ in DECISION_REASONS})


def test_the_resolution_table_lists_exactly_the_causes_a_refusal_records() -> None:
    # The table's row says admission still records it; a change there has to change the row.
    assert f'"{GENERIC_ADMISSION_REASON}"' in ADMISSION.read_text(encoding="utf-8")
    assert GENERIC_ADMISSION_REASON not in RESOLUTION_CODES
    _same(
        "Why a request was refused before admission",
        set(RESOLUTION_CODES) | {GENERIC_ADMISSION_REASON},
    )


def test_the_console_table_lists_every_console_code_at_its_status() -> None:
    table = _same("Console API codes", set(CONSOLE_CODES))
    wrong = {
        code: status for code, status in table.items() if status != str(CONSOLE_CODES[code][0])
    }
    assert not wrong, f"statuses that differ from the console's: {wrong}"


def test_each_command_and_intake_table_lists_every_code_its_class_is_raised_with() -> None:
    passed: dict[str, int] = {}
    for family in FAMILIES:
        codes, through = family_codes(family)
        assert codes, family.section
        codes |= {code for code, section in PRINTED.items() if section == family.section}
        codes |= {code for code, (section, _) in RECORDED.items() if section == family.section}
        table = _same(family.section, codes)
        if family.status is not None:
            wrong = {
                code: status
                for code, status in table.items()
                if status != str(family.status.get(code, 400))
            }
            assert not wrong, f"{family.section}, statuses the handler does not answer: {wrong}"
        for where, count in through.items():
            passed[where] = passed.get(where, 0) + count
    assert passed == {where: count for where, (count, _) in PASSED_THROUGH.items()}


def _synthetic(source: str) -> tuple[set[str], int]:
    """What `_raised` reads from a module written here, raising `SyntheticError`."""
    return _raised(_read("synthetic", ast.parse(source)), {"SyntheticError"}, set())


def test_the_reader_takes_a_parameter_s_default_where_a_call_leaves_it_out() -> None:
    # Each function raises its `code` parameter; the calls below give some and leave others out.
    # A left-out code is the parameter's default, positional, positional-only or keyword-only,
    # and a method's place among the arguments does not count its `self`.
    codes, through = _synthetic(
        """
def refuse(value, code="DEFAULTED"):
    raise SyntheticError(code)


def refuse_by_keyword(value, *, code="KEYWORD_DEFAULTED"):
    raise SyntheticError(code)


def refuse_by_place(code="PLACE_DEFAULTED", /):
    raise SyntheticError(code)


def refuse_given(value, code):
    raise SyntheticError(code)


class Checker:
    def check(self, code="METHOD_DEFAULTED"):
        raise SyntheticError(code)

    @staticmethod
    def check_static(code="STATIC_DEFAULTED"):
        raise SyntheticError(code)


def callers(checker):
    refuse(1)
    refuse(2, "PASSED")
    refuse(3, code="NAMED")
    refuse_by_keyword(4)
    refuse_by_keyword(5, code="KEYWORD_PASSED")
    refuse_by_place()
    refuse_given(6, "GIVEN")
    checker.check()
    checker.check("METHOD_PASSED")
    Checker.check_static("STATIC_PASSED")
"""
    )
    assert codes == {
        "DEFAULTED",
        "PASSED",
        "NAMED",
        "KEYWORD_DEFAULTED",
        "KEYWORD_PASSED",
        "PLACE_DEFAULTED",
        "GIVEN",
        "METHOD_DEFAULTED",
        "METHOD_PASSED",
        "STATIC_PASSED",
    }
    assert through == 0


def test_the_reader_does_not_take_a_spread_call_as_leaving_a_code_out() -> None:
    # `*` or `**` can carry the code, so neither call is read as leaving it to the default:
    # each raise counts as passing a code through.
    for call in ("refuse(*arguments)", "refuse(1, **options)"):
        codes, through = _synthetic(
            f"""
def refuse(value, code="DEFAULTED"):
    raise SyntheticError(code)


def caller(arguments, options):
    {call}
"""
        )
        assert (codes, through) == (set(), 1), call


def test_a_family_that_passes_another_error_s_codes_through_links_to_their_table() -> None:
    sections = _sections()
    owners = {
        where: family.section
        for family in FAMILIES
        for path in _module_paths(family)
        if (where := path.relative_to(ROOT).as_posix()) in PASSED_THROUGH
    }
    for where, (_, target) in PASSED_THROUGH.items():
        if target is None or target == owners[where]:
            continue
        anchor = "(#" + target.lower().replace(" ", "-") + ")"
        assert anchor in "\n".join(sections[owners[where]]), (owners[where], target)


def test_every_code_a_command_prints_as_text_is_assigned_a_table() -> None:
    printed = set()
    for module in COMMAND_MODULES:
        tree = ast.parse((SOURCES / "execbound" / module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                printed |= set(re.findall(r"refused: ([A-Z][A-Z0-9_]+)\.", node.value))
    assert printed == set(PRINTED)


def test_every_code_a_collection_run_records_without_raising_is_written_where_it_says() -> None:
    for code, (_, modules) in RECORDED.items():
        for module in modules:
            tree = ast.parse((SOURCES / "execbound" / module).read_text(encoding="utf-8"))
            written = {
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            assert code in written, (code, module)
