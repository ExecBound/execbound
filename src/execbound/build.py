# SPDX-License-Identifier: AGPL-3.0-only
"""What is running: the package version and the source commit, for readiness to report.

Identifiers only. The commit comes from ``EXECBOUND_COMMIT`` (set at image build from the
source commit) or, where the platform injects it, ``RENDER_GIT_COMMIT``; anything that is
not a hexadecimal commit id is reported as nothing rather than echoed.
"""

import importlib.metadata
import os
import re
from collections.abc import Mapping

COMMIT_VARIABLES = ("EXECBOUND_COMMIT", "RENDER_GIT_COMMIT")
_COMMIT = re.compile(r"[0-9a-f]{7,40}")


def package_version() -> str:
    """The installed distribution's version; a placeholder when it is not installed."""
    try:
        return importlib.metadata.version("execbound")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def running_commit(environ: Mapping[str, str] | None = None) -> str | None:
    """The source commit of the running process, or None when nothing states it."""
    env = os.environ if environ is None else environ
    for name in COMMIT_VARIABLES:
        value = env.get(name, "").strip().lower()
        if _COMMIT.fullmatch(value):
            return value
    return None
