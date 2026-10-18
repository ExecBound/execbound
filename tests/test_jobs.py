# SPDX-License-Identifier: AGPL-3.0-only
"""`jobs.for_each_tenant`: a tenant's refusal is its outcome, and the process's is the run's.

While the database is at another schema revision, as during an upgrade, every tenant is
skipped and the run exits 0. A database whose grants are not what this process's plugins
claim stops the run (#496), so the command can say which of the two things is wrong.
"""

from uuid import uuid4

import pytest

from execbound import jobs
from execbound.db import DormantGrantsRefused, UnsafeDatabaseRole


def refusing(monkeypatch, error):
    """Every authentication raises ``error``; returns the tokens it was asked about."""
    asked = []

    def authenticate(db, token):
        asked.append(token)
        raise error

    monkeypatch.setattr(jobs, "authenticate", authenticate)
    return asked


def never(identity):
    pytest.fail("no tenant's step may run when its authentication was refused")


def test_a_revision_mismatch_skips_every_tenant(monkeypatch):
    asked = refusing(monkeypatch, UnsafeDatabaseRole("Database revision mismatch"))
    tokens = {uuid4(): "first", uuid4(): "second"}
    outcomes = jobs.for_each_tenant(object(), tokens, never, command="recover")
    assert outcomes == {str(tenant): {"skipped": "DEPENDENCY_UNAVAILABLE"} for tenant in tokens}
    assert asked == ["first", "second"]


def test_a_refusal_for_the_dormant_grants_stops_the_run(monkeypatch):
    asked = refusing(monkeypatch, DormantGrantsRefused("Unsafe dormant grants"))
    tokens = {uuid4(): "first", uuid4(): "second"}
    with pytest.raises(DormantGrantsRefused):
        jobs.for_each_tenant(object(), tokens, never, command="recover")
    assert asked == ["first"]
