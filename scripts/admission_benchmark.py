# SPDX-License-Identifier: AGPL-3.0-only
"""Measure admission throughput and latency under the tenant fence against local fixtures.

Concurrent agents in one tenant (and optionally two) submit distinct actions that the
active policy denies. A denied admission takes the full serialized path (tenant fence,
identity checks, resolution, Cedar evaluation, audit append and the execution row)
without any reservation or provider effect, so it can repeat indefinitely and shows what
the per-tenant lock costs. The numbers describe the machine they ran on; they are a
floor for a laptop-class database, not a pilot load test.

    uv run execbound seed-validation --seed bench-1 --output local-data/bench-1
    uv run python scripts/admission_benchmark.py --private local-data/bench-1 --seconds 8 \\
        --concurrency 1,2,4,8,16 --tenants 2 --output local-data/bench-report.json

Run within 300 seconds of seeding: the fixtures' trusted context expires after that.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from execbound.db import Database
from execbound.identity import Identity, authenticate
from execbound.surfaces.configuration import load_runtime
from execbound_harness.validation_run import action_request, private_json

DENIED_TARGET = "domain-controller"
ACTION = "endpoint.isolate"
MAX_CONCURRENCY = 16


def participants(
    private: Path, db: Database, tenants: int
) -> list[tuple[Identity, dict[str, Any]]]:
    fixture = private_json(private / "fixture.json")
    credentials = private_json(private / "credentials.json")
    selected = []
    for tenant in fixture["tenants"][:tenants]:
        target = next(t for t in tenant["targets"] if t["label"] == DENIED_TARGET)
        actor = next(a for a in credentials[tenant["tenant_id"]] if a["label"] == "agent-0")
        selected.append((authenticate(db, actor["token"]), target))
    return selected


def _worker(
    runtime: Any,
    identity: Identity,
    target: dict[str, Any],
    stop_at: float,
    prefix: str,
    sink: list[tuple[float, str]],
) -> None:
    sequence = 0
    while time.monotonic() < stop_at:
        body = action_request(target, ACTION, f"{prefix}-{sequence}")
        sequence += 1
        started = time.perf_counter()
        try:
            state = runtime.execute(identity, json.dumps(body).encode("utf-8")).state
        except Exception as error:
            # The report records only the failure class; nothing else is retried.
            state = "ERROR:" + getattr(error, "code", type(error).__name__)
        sink.append((time.perf_counter() - started, state))


def measure(
    runtime: Any,
    actors: list[tuple[Identity, dict[str, Any]]],
    concurrency: int,
    seconds: float,
    label: str,
) -> dict[str, Any]:
    sink: list[tuple[float, str]] = []
    stop_at = time.monotonic() + seconds
    threads = [
        threading.Thread(
            target=_worker,
            args=(runtime, *actors[index % len(actors)], stop_at, f"{label}-{index}", sink),
            daemon=True,
        )
        for index in range(concurrency)
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started
    latencies = sorted(latency for latency, _ in sink)
    states = Counter(state for _, state in sink)

    def percentile(fraction: float) -> float:
        if not latencies:
            return 0.0
        return latencies[min(len(latencies) - 1, int(round(fraction * (len(latencies) - 1))))]

    return {
        "label": label,
        "concurrency": concurrency,
        "tenants": len({identity.tenant_id for identity, _ in actors}),
        "seconds": round(elapsed, 3),
        "admissions": len(sink),
        "per_second": round(len(sink) / elapsed, 1) if elapsed else 0.0,
        "latency_ms": {
            "p50": round(percentile(0.5) * 1000, 1),
            "p95": round(percentile(0.95) * 1000, 1),
            "max": round((latencies[-1] if latencies else 0.0) * 1000, 1),
            "mean": round(statistics.fmean(latencies) * 1000, 1) if latencies else 0.0,
        },
        "states": dict(sorted(states.items())),
    }


def run(
    private: Path, database_url: str, *, seconds: float, concurrency_levels: list[int], tenants: int
) -> dict[str, Any]:
    if tenants not in (1, 2) or any(
        not 1 <= level <= MAX_CONCURRENCY for level in concurrency_levels
    ):
        raise ValueError("Invalid benchmark parameters")
    db = Database(database_url)
    runtime, _ = load_runtime(private / "gateway.json", db)
    try:
        actors = participants(private, db, tenants)
        for identity, target in actors:
            probe = runtime.execute(
                identity, json.dumps(action_request(target, ACTION, "bench-probe")).encode("utf-8")
            )
            if probe.state != "DENIED":
                raise ValueError(
                    f"Probe admission is {probe.state}, not DENIED; reseed the fixtures"
                )
        one_tenant = [
            measure(runtime, actors[:1], level, seconds, f"one-{level}")
            for level in concurrency_levels
        ]
        two_tenants = None
        if tenants == 2:
            two_tenants = measure(runtime, actors, max(concurrency_levels), seconds, "two")
    finally:
        for connector in runtime.connectors.values():
            connector.close()
        db.close()
    return {
        "version": 1,
        "cpu_count": os.cpu_count(),
        "seconds_per_level": seconds,
        "path": "denied admission: fence, identity, resolution, evaluation, audit, execution row",
        "one_tenant": one_tenant,
        "two_tenants": two_tenants,
    }


def render(report: dict[str, Any]) -> str:
    rows = list(report["one_tenant"]) + ([report["two_tenants"]] if report["two_tenants"] else [])
    lines = [
        "| Tenants | Concurrency | Admissions/s | p50 ms | p95 ms | Max ms | States |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lat = row["latency_ms"]
        states = ", ".join(f"{state} {count}" for state, count in row["states"].items())
        lines.append(
            f"| {row['tenants']} | {row['concurrency']} | {row['per_second']} "
            f"| {lat['p50']} | {lat['p95']} | {lat['max']} | {states} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--private", type=Path, required=True, help="Fixture directory")
    parser.add_argument("--seconds", type=float, default=8.0)
    parser.add_argument(
        "--concurrency", default="1,2,4,8,16", help="Comma-separated levels, each at most 16"
    )
    parser.add_argument("--tenants", type=int, choices=(1, 2), default=2)
    parser.add_argument("--output", type=Path, required=True, help="New JSON report file")
    args = parser.parse_args(argv)
    load_dotenv()
    try:
        levels = [int(item) for item in args.concurrency.split(",") if item.strip()]
        report = run(
            args.private,
            os.environ["DATABASE_URL"],
            seconds=args.seconds,
            concurrency_levels=levels,
            tenants=args.tenants,
        )
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    except (KeyError, ValueError, OSError) as error:
        detail = error if isinstance(error, ValueError) else type(error).__name__
        print(f"Benchmark stopped: {detail}.", file=sys.stderr)
        return 2
    print(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
