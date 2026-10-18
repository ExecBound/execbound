# SPDX-License-Identifier: AGPL-3.0-only
"""A table of patterns the tree may never contain, each with the invariant it protects and
where that invariant is written down (#262, #265).

A rule allows a file only by naming it in the table beside the reason. There are no inline
suppression comments, so the table is the one place that says what the tree may contain, and
a stale allowance fails too: every listed file must exist and must still match, so an
exception disappears the day it is no longer needed. To add a rule, add a row.

This file is excluded from every scan. It holds each pattern as data, so it would otherwise
be its own only violation.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SELF = "tests/test_repository_rules.py"
# Build output, dependencies and working data are not the tree a rule describes.
SKIPPED = {"__pycache__", ".venv", ".tools", "local-data", "dist", "node_modules", ".git"}
PYTHON = (".py",)
WORKFLOW = (".yml", ".yaml")


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    roots: tuple[str, ...]
    invariant: str
    suffixes: tuple[str, ...] = PYTHON
    # relative path -> why this file is allowed to match.
    allow: dict[str, str] = field(default_factory=dict)


RULES = (
    Rule(
        name="rendered-password",
        pattern=r"hide_password\s*=\s*False",
        # .github is not among the roots: workflow files are checked separately, and a core
        # test never reads one (#496).
        roots=("src", "scripts"),
        suffixes=PYTHON + WORKFLOW,
        invariant=(
            "A connection string is never rendered with its password outside the setup "
            "script; use connection.with_database_name, which returns a URL object (#262)."
        ),
        allow={"scripts/local_setup.py": "writing .env is this script's purpose"},
    ),
    Rule(
        name="no-redirects",
        pattern=r"follow_redirects\s*=\s*True",
        roots=("src", "scripts"),
        invariant=(
            "No outbound request follows a redirect to a destination it did not choose "
            "(docs/THREAT_MODEL.md T3.1, T6.10)."
        ),
    ),
    Rule(
        name="no-ambient-transport",
        pattern=r"trust_env\s*=\s*True",
        roots=("src", "scripts"),
        invariant=(
            "No client takes its proxies or certificates from the environment "
            "(docs/THREAT_MODEL.md T3.1)."
        ),
    ),
    Rule(
        name="no-parameter-echo",
        pattern=r"hide_parameters\s*=\s*False",
        roots=("src", "scripts"),
        invariant=(
            "SQL parameters, which carry tenant data, never reach a log or a diagnostic; "
            "the engine helpers set the opposite (docs/DATA_MODEL.md)."
        ),
    ),
    Rule(
        name="no-unverified-tls",
        pattern=r"verify\s*=\s*False",
        roots=("src", "scripts"),
        invariant="TLS verification is never disabled on any transport (docs/EXECUTION.md).",
    ),
    Rule(
        name="nosec-with-reason",
        # The marker must carry its code or codes and then a reason: `# nosec B### - why`.
        pattern=r"#\s*nosec(?!(?:\s+B\d{3})+\s+-\s+\S)",
        roots=("src", "scripts"),
        invariant=(
            "Every bandit suppression names the finding it suppresses and says why it is "
            "safe, so a reader can see what was accepted and a new finding of the same code "
            "is not silently covered."
        ),
    ),
    Rule(
        name="hand-written-secret-assertion",
        pattern=r"[\"'][^\"']*\b(?:eb1|hs1|mo1|ebi1|ebv1|ebp1|sg1)\.[^\"']*[\"']\s+not in",
        roots=("tests",),
        invariant=(
            "A test proves an output carries no secret with assert_secret_free, which reads "
            "the same definition the runtime guards do, rather than naming one prefix it "
            "happens to remember (CONTRIBUTING.md, #265)."
        ),
    ),
)


def covered(rule: Rule, root: Path) -> dict[str, list[str]]:
    """Every file a rule reads under `root`, as relative path to lines."""
    found = {}
    for directory in rule.roots:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if (
                path.suffix not in rule.suffixes
                or not path.is_file()
                or relative == SELF
                or SKIPPED & set(path.relative_to(root).parts)
            ):
                continue
            found[relative] = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return found


def hits(rule: Rule, root: Path) -> dict[str, list[str]]:
    """Matching files, each with its `path:line: text` lines."""
    compiled = re.compile(rule.pattern)
    matched = {}
    for relative, lines in covered(rule, root).items():
        found = [
            f"{relative}:{number}: {line.strip()[:120]}"
            for number, line in enumerate(lines, start=1)
            if compiled.search(line)
        ]
        if found:
            matched[relative] = found
    return matched


@pytest.mark.parametrize("rule", RULES, ids=[rule.name for rule in RULES])
def test_no_file_breaks_a_rule(rule):
    found = hits(rule, ROOT)
    broken = sorted(
        line for path, lines in found.items() if path not in rule.allow for line in lines
    )
    assert broken == [], rule.invariant + "\n" + "\n".join(broken)


@pytest.mark.parametrize("rule", RULES, ids=[rule.name for rule in RULES])
def test_no_allowance_outlives_its_reason(rule):
    found = hits(rule, ROOT)
    stale = sorted(allowed for allowed in rule.allow if allowed not in found)
    assert stale == [], "allowlist entry no longer needed: " + ", ".join(stale)


def test_the_table_is_well_formed():
    assert len({rule.name for rule in RULES}) == len(RULES)
    for rule in RULES:
        assert rule.roots and rule.suffixes and rule.invariant.endswith(".")
        re.compile(rule.pattern)
        for allowed, reason in rule.allow.items():
            assert (ROOT / allowed).is_file() and reason


# Tests of the test. The table is only worth having if it reads a tree correctly, so it is
# exercised against a temporary one rather than only against this repository.
SAMPLE = Rule(
    name="sample",
    pattern=r"forbidden",
    roots=("src",),
    invariant="Nothing may say the forbidden word.",
    allow={"src/excused.py": "it is the example"},
)


@pytest.fixture
def tree(tmp_path):
    source = tmp_path / "src"
    (source / "nested").mkdir(parents=True)
    (source / "__pycache__").mkdir()
    (source / "clean.py").write_text("ordinary = 1\n", encoding="utf-8")
    (source / "nested/broken.py").write_text("x = 1\ny = 'forbidden'\n", encoding="utf-8")
    (source / "excused.py").write_text("z = 'forbidden'\n", encoding="utf-8")
    (source / "__pycache__/cached.py").write_text("q = 'forbidden'\n", encoding="utf-8")
    (source / "notes.txt").write_text("forbidden\n", encoding="utf-8")
    return tmp_path


def test_a_matching_file_is_reported_with_its_line(tree):
    found = hits(SAMPLE, tree)
    assert found["src/nested/broken.py"] == ["src/nested/broken.py:2: y = 'forbidden'"]


def test_an_allowed_file_and_a_clean_file_are_not_reported(tree):
    found = hits(SAMPLE, tree)
    broken = [path for path in found if path not in SAMPLE.allow]
    assert broken == ["src/nested/broken.py"]
    assert "src/clean.py" not in found


def test_an_excluded_directory_and_an_unread_suffix_are_not_read(tree):
    read = covered(SAMPLE, tree)
    assert "src/__pycache__/cached.py" not in read
    assert "src/notes.txt" not in read
    assert set(read) == {"src/clean.py", "src/nested/broken.py", "src/excused.py"}


def test_an_allowance_that_no_longer_matches_is_reported_as_stale(tree):
    (tree / "src/excused.py").write_text("z = 'ordinary'\n", encoding="utf-8")
    found = hits(SAMPLE, tree)
    assert [allowed for allowed in SAMPLE.allow if allowed not in found] == ["src/excused.py"]
