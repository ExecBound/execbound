# SPDX-License-Identifier: AGPL-3.0-only
"""Load `scripts/console_sbom.py` by path, as `test_board_css.py` loads its generator."""

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT / "console" / "pnpm-lock.yaml"
SCRIPT = ROOT / "scripts" / "console_sbom.py"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("console_sbom", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
