# SPDX-License-Identifier: AGPL-3.0-only
"""The step-up's purpose table names every core change the step-up asks for (#678).

The console turns a refused change into words through one table in
`console/src/lib/step-up-purpose.ts`, keyed by method and the API's path template. This holds
the table to the served document both ways: every non-GET operation `guards.steps_up` matches
has a phrase, and every phrase is for a route the document serves, unless it waits in `PENDING`
for a route that has not landed yet. A pending route that is served fails here, so the set
cannot go stale: the change that serves it takes it out and confirms its phrase.
"""

import json
import re
from pathlib import Path

from execbound.surfaces.console_api.guards import steps_up

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "console" / "openapi" / "console-v1.json"
TABLE = ROOT / "console" / "src" / "lib" / "step-up-purpose.ts"
V = "/api/console/v1"

# Routes written into the table before they land. Each change that serves one takes it out of
# here in the same change; the last of the monitoring connection and reporting source routes
# landed with the source routes (#678), so none waits now.
PENDING: set[tuple[str, str]] = set()


def served() -> set[tuple[str, str]]:
    document = json.loads(DOCUMENT.read_text(encoding="utf-8"))
    return {
        (method.upper(), path)
        for path, operations in document["paths"].items()
        for method in operations
        if method.lower() in {"post", "put", "patch", "delete"}
    }


def entries() -> set[tuple[str, str]]:
    text = TABLE.read_text(encoding="utf-8").replace("${V}", V)
    return set(re.findall(r"`(POST|PUT|PATCH|DELETE) (/api/console/v1/[^`]+)`", text))


def test_su_every_core_step_up_route_has_a_purpose():
    protected = {(method, path) for method, path in served() if steps_up(path)}
    missing = sorted(protected - entries())
    assert not missing, (
        f"No step-up purpose for {missing}: a change that adds a core step-up route adds its "
        "phrase to console/src/lib/step-up-purpose.ts in the same change"
    )


def test_su_every_purpose_is_a_served_route_or_pending():
    stray = sorted(entries() - served() - PENDING)
    assert not stray, f"Purposes for routes the document does not serve: {stray}"
    stale = sorted(PENDING & served())
    assert not stale, f"Served now, so no longer pending: {stale}; take them out of PENDING"


def test_su_policy_mode_and_samples_are_ordinary_entries():
    for path in (
        V + "/policy/{bundle_id}/activate",
        V + "/tenant/mode",
        V + "/samples",
        V + "/samples/refresh",
    ):
        assert ("POST", path) in entries() and ("POST", path) in served()
        assert ("POST", path) not in PENDING
        assert steps_up(path)
