# SPDX-License-Identifier: AGPL-3.0-only
"""The admission benchmark drives only denied admissions and reports per level."""

import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
benchmark = importlib.import_module("admission_benchmark")


def test_benchmark_reports_denied_admissions_per_level(seeded, tmp_path, monkeypatch):
    from execbound_harness.validation_demo import seed_validation

    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    private = tmp_path / "bench"
    seed_validation(
        os.environ["TEST_MIGRATION_DATABASE_URL"],
        private,
        seed="bench-test",
        gateway_port=8190,
        endpoint_port=8191,
        identity_port=8192,
    )
    report = benchmark.run(
        private, os.environ["TEST_DATABASE_URL"], seconds=1.0, concurrency_levels=[1, 2], tenants=2
    )
    assert [row["concurrency"] for row in report["one_tenant"]] == [1, 2]
    for row in report["one_tenant"] + [report["two_tenants"]]:
        assert row["admissions"] > 0 and row["per_second"] > 0
        assert row["states"] == {"DENIED": row["admissions"]}
        assert row["latency_ms"]["p50"] <= row["latency_ms"]["p95"] <= row["latency_ms"]["max"]
    assert report["two_tenants"]["tenants"] == 2 and report["one_tenant"][0]["tenants"] == 1
    assert "Admissions/s" in benchmark.render(report)
    output = tmp_path / "report.json"
    assert (
        benchmark.main(
            [
                "--private",
                str(private),
                "--seconds",
                "0.5",
                "--concurrency",
                "1",
                "--tenants",
                "1",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.exists()
    assert (
        benchmark.main(
            [
                "--private",
                str(private),
                "--seconds",
                "0.5",
                "--concurrency",
                "17",
                "--tenants",
                "1",
                "--output",
                str(tmp_path / "r2.json"),
            ]
        )
        == 2
    )
