# SPDX-License-Identifier: AGPL-3.0-only
"""The runtime never admits more concurrent calls than the database pool can serve."""

import importlib
import os
import sys
from pathlib import Path

import pytest
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import world as world

from execbound.db import Database
from execbound.runtime import Runtime

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
benchmark = importlib.import_module("admission_benchmark")


def test_default_concurrency_is_the_pool_capacity_and_more_is_refused(db, connector):
    default = Database(os.environ["TEST_DATABASE_URL"])
    try:
        assert default.capacity == 13 and Runtime(default, [connector]).concurrency == 13
    finally:
        default.close()
    # The test fixture uses a smaller pool; the runtime follows whatever pool it is given.
    assert Runtime(db, [connector]).concurrency == min(16, db.capacity)
    assert Runtime(db, [connector], concurrency=db.capacity).concurrency == db.capacity
    with pytest.raises(ValueError, match="exceeds the database pool"):
        Runtime(db, [connector], concurrency=db.capacity + 1)
    small = Database(os.environ["TEST_DATABASE_URL"], pool_size=2, max_overflow=1)
    try:
        assert small.capacity == 3 and Runtime(small, [connector]).concurrency == 3
        with pytest.raises(ValueError):
            Runtime(small, [connector], concurrency=4)
    finally:
        small.close()
    with pytest.raises(ValueError, match="Invalid database pool size"):
        Database(os.environ["TEST_DATABASE_URL"], pool_size=0)


def test_runtime_at_its_cap_never_hits_the_pool_timeout(seeded, tmp_path, monkeypatch):
    from execbound_harness.validation_demo import seed_validation

    private = tmp_path / "cap"
    seed_validation(
        os.environ["TEST_MIGRATION_DATABASE_URL"],
        private,
        seed="pool-cap",
        gateway_port=8193,
        endpoint_port=8194,
        identity_port=8195,
    )
    report = benchmark.run(
        private, os.environ["TEST_DATABASE_URL"], seconds=3.0, concurrency_levels=[13], tenants=1
    )
    [row] = report["one_tenant"]
    assert row["admissions"] > 0
    assert row["states"] == {"DENIED": row["admissions"]}, row["states"]
    assert row["latency_ms"]["max"] < 5000
