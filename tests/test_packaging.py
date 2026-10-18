# SPDX-License-Identifier: AGPL-3.0-only
"""The runtime package ships without demo or validation harness code (#40)."""

import re
import sys
import tomllib
from pathlib import Path

import pytest

import execbound
from execbound.cli import main


def test_runtime_package_has_no_harness_modules():
    root = Path(execbound.__file__).parent
    modules = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.py"))
    harness = [m for m in modules if re.search(r"(^|/)(validation_\w+|\w*demo)\.py$", m)]
    assert harness == []
    project = tomllib.loads((root.parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/execbound"]
    assert (root.parent / "execbound_harness" / "validation_demo.py").is_file()


def test_seed_validation_refuses_without_the_harness(monkeypatch, capsys, tmp_path):
    monkeypatch.setitem(sys.modules, "execbound_harness.validation_demo", None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["execbound", "seed-validation", "--seed", "x", "--output", str(tmp_path / "n")],
    )
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert "harness is not installed" in capsys.readouterr().err
