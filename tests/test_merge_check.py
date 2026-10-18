# SPDX-License-Identifier: AGPL-3.0-only
"""The pre-merge guard against a forked alembic revision graph."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("merge_check", "scripts/merge_check.py")
assert spec is not None and spec.loader is not None
merge_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge_check)


def graph(*pairs: tuple[str, str | None]) -> dict[str, frozenset[str]]:
    return {revision: merge_check.parents_of(parent) for revision, parent in pairs}


def migration(revision: str, parent: str | None) -> str:
    parent_literal = "None" if parent is None else f'"{parent}"'
    return f'"""A migration."""\n\nrevision = "{revision}"\ndown_revision = {parent_literal}\n'


def test_two_migrations_numbered_from_one_parent_are_reported_as_a_fork():
    # The case this check exists for, taken from 17 September 2026: main merged
    # 0031_scout_rules while a branch already held 0031_reported_failure, both on
    # 0030_scout_agents. Each side alone has exactly one head.
    base = graph(
        ("0030_scout_agents", "0029_claim_clock"), ("0031_scout_rules", "0030_scout_agents")
    )
    branch = graph(
        ("0030_scout_agents", "0029_claim_clock"),
        ("0031_reported_failure", "0030_scout_agents"),
    )
    assert merge_check.heads(base) == {"0031_scout_rules"}
    assert merge_check.heads(branch) == {"0031_reported_failure"}

    problems = merge_check.report(base, branch, "origin/main")

    assert len(problems) == 1
    assert "2 alembic heads" in problems[0]
    assert "0031_scout_rules (origin/main, parent 0030_scout_agents)" in problems[0]
    assert "0031_reported_failure (this branch, parent 0030_scout_agents)" in problems[0]


def test_a_branch_built_on_the_current_head_merges_cleanly():
    base = graph(
        ("0030_scout_agents", "0029_claim_clock"), ("0031_scout_rules", "0030_scout_agents")
    )
    branch = dict(base) | graph(("0032_reported_failure", "0031_scout_rules"))

    assert merge_check.report(base, branch, "origin/main") == []


def test_a_branch_that_adds_no_migration_merges_cleanly():
    base = graph(("0030_scout_agents", "0029_claim_clock"))

    assert merge_check.report(base, dict(base), "origin/main") == []


def test_rewriting_a_merged_migrations_parent_is_refused():
    # Re-parenting your own unmerged migration is the fix; re-parenting one the base branch
    # already carries rewrites frozen history and has to be caught separately.
    base = graph(("0031_scout_rules", "0030_scout_agents"))
    branch = graph(("0031_scout_rules", "0029_claim_clock"))

    problems = merge_check.report(base, branch, "origin/main")

    assert any("frozen history" in problem for problem in problems)
    assert any("parent 0030_scout_agents on origin/main" in problem for problem in problems)


def test_a_cycle_is_reported_rather_than_passing_quietly():
    cyclic = graph(("a", "b"), ("b", "a"))

    problems = merge_check.report({}, cyclic, "origin/main")

    assert len(problems) == 1
    assert "cycle" in problems[0]


def test_a_merge_revision_joining_two_lines_leaves_one_head():
    union = graph(("0031_one", "0030_base"), ("0031_two", "0030_base"), ("0030_base", None))
    union["0032_merge"] = merge_check.parents_of(("0031_one", "0031_two"))

    assert merge_check.heads(union) == {"0032_merge"}
    assert merge_check.report({}, union, "origin/main") == []


def test_a_parent_is_read_from_every_form_alembic_accepts():
    assert merge_check.parents_of(None) == frozenset()
    assert merge_check.parents_of("0030_base") == frozenset({"0030_base"})
    assert merge_check.parents_of(("a", "b")) == frozenset({"a", "b"})
    assert merge_check.parents_of(["a"]) == frozenset({"a"})
    assert merge_check.parents_of(7) == frozenset()


def test_a_revision_and_its_parent_are_read_without_importing_the_module():
    read = merge_check.read_revision(migration("0031_scout_rules", "0030_scout_agents"))

    assert read == ("0031_scout_rules", frozenset({"0030_scout_agents"}))


def test_the_first_revision_declares_no_parent():
    assert merge_check.read_revision(migration("0001_start", None)) == ("0001_start", frozenset())


def test_a_module_that_declares_no_revision_is_ignored():
    assert merge_check.read_revision('"""Not a migration."""\n') is None
    assert merge_check.read_revision("revision = 3\n") is None
    assert merge_check.read_revision("revision = 'x'\ndown_revision = (\n") is None


def test_the_working_tree_is_collected_from_the_versions_directory(tmp_path: Path):
    versions = tmp_path / merge_check.VERSIONS
    versions.mkdir(parents=True)
    (versions / "0001_start.py").write_text(migration("0001_start", None), encoding="utf-8")
    (versions / "0002_next.py").write_text(migration("0002_next", "0001_start"), encoding="utf-8")
    (versions / "__init__.py").write_text("", encoding="utf-8")

    collected = merge_check.collect_tree(tmp_path)

    assert collected == {"0001_start": frozenset(), "0002_next": frozenset({"0001_start"})}
    assert merge_check.heads(collected) == {"0002_next"}
