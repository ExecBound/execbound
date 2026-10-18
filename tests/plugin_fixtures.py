# SPDX-License-Identifier: AGPL-3.0-only
"""Installing the sample plugin as ``execbound.<name>``, and reading the logs it causes.

`install` puts the sample file in ``sys.modules`` under the name core resolves, so a test
exercises the real lookup rather than a hook. `monkeypatch` removes it after the test.
"""

import importlib.util
import io
import json
import logging
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from execbound import logging_schema

SAMPLE = Path(__file__).resolve().parent / "plugins" / "sample_plugin.py"


def install(
    monkeypatch: pytest.MonkeyPatch, name: str = "sample_plugin", **changes: Any
) -> ModuleType:
    spec = importlib.util.spec_from_file_location("execbound." + name, SAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "execbound." + name, module)
    spec.loader.exec_module(module)
    if changes:
        module.PLUGIN = replace(module.PLUGIN, **changes)
    return module


@pytest.fixture
def sample(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    return install(monkeypatch)


@pytest.fixture
def captured():
    stream = io.StringIO()
    handler = logging_schema.capture_handler(stream)
    logger = logging.getLogger("execbound")
    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


def events(stream: io.StringIO, name: str) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    return [record for record in records if record["event"] == name]
