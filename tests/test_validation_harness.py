# SPDX-License-Identifier: AGPL-3.0-only
"""Fresh two-provider startup, browser approval, MCP retry and offline reproduction."""

import os
import socket
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from signal_fixtures import insert_source
from sqlalchemy import text
from test_migration_without_bypass import fenced
from test_validation_ports import held_listeners as held_listeners


def test_fresh_validation_package_runs_all_boundaries(
    admin_engine, seeded, tmp_path, monkeypatch, held_listeners
):
    from execbound.replay.fixture import run_check
    from execbound_harness.validation_demo import seed_validation
    from execbound_harness.validation_run import run_demo

    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    listeners = held_listeners("gateway", "endpoint", "identity")
    ports = [listeners[name].getsockname()[1] for name in ("gateway", "endpoint", "identity")]
    private, evidence = tmp_path / "private", tmp_path / "evidence"
    seed_validation(
        os.environ["TEST_MIGRATION_DATABASE_URL"],
        private,
        seed=str(uuid4()),
        gateway_port=ports[0],
        endpoint_port=ports[1],
        identity_port=ports[2],
    )
    manifest = run_demo(private, evidence, listeners)
    assert manifest["tenant_count"] == 2
    assert len(manifest["executions"]) == 16
    assert manifest["providers_stopped_before_replay"]
    assert manifest["live_fingerprints_unchanged"]
    assert len(list(evidence.glob("*.png"))) == 8
    assert (evidence / "comparison-1" / "report.json").is_file()
    assert (evidence / "uncertain-replay-0" / "report.json").is_file()
    # Each tenant's history as a sanitized regression fixture, which checks clean (RF10).
    for index in range(2):
        fixture, found = run_check(evidence / f"tenant-{index}.fixture.json")
        assert found == [] and fixture.expected.baseline.decisions and fixture.candidates
    private_names = {
        "credentials.json",
        "gateway.json",
        "endpoint-accounts.json",
        "identity-accounts.json",
    }
    assert not private_names & {path.name for path in evidence.rglob("*")}
    for port in ports:
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", port)) != 0


def test_the_live_fingerprint_reads_the_columns_the_runtime_can_of_a_partly_readable_table(
    db, admin_engine, seeded
):
    """`signal_admit` moves a source's health columns, so the fingerprint that proves replay
    changed no live state reads `signal_sources` too: every column the runtime holds, and
    never the token digests it does not."""
    from execbound_harness.validation_run import snapshot

    tenant = seeded["tenants"][0]
    tenants = [{"tenant_id": str(tenant)}]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        source, _ = insert_source(conn, tenant, seeded["principals"][0], datetime.now(UTC))
    before = snapshot(db, tenants)
    assert snapshot(db, tenants) == before

    def owner_sets(assignment: str) -> None:
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(f"UPDATE execbound.signal_sources SET {assignment} WHERE source_id = :s"),
                {"s": source},
            )

    owner_sets("token_hash = repeat('c', 64)")
    assert snapshot(db, tenants) == before
    owner_sets("rate_count = rate_count + 1")
    assert snapshot(db, tenants) != before


def test_demo_services_gateway_readiness_presents_the_configured_readiness_host(
    admin_engine, tmp_path, monkeypatch, held_listeners
):
    """`DemoServices.start`'s readiness probe for the gateway must present whatever ``Host``
    the caller names: the gateway refuses a request whose ``Host`` does not match its
    configured origin's netloc (``execbound.app``'s ``response_headers`` middleware, which
    always holds a `HumanConfig` since a private configuration file always names an origin).
    A gateway fronted by a tunnel has its origin rewritten to the tunnel's https host and needs
    exactly this for its readiness probe to succeed rather than time out, which is what a live
    trial found. A probe that still presents the loopback host must still be refused, so the
    fix does not weaken the gateway's own check."""
    import json

    import httpx

    from execbound_harness.gate_demo import seed_gate
    from execbound_harness.validation_run import DemoServices

    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    listeners = held_listeners("gateway", "endpoint")
    ports = [listeners[name].getsockname()[1] for name in ("gateway", "endpoint")]
    output = tmp_path / "gate"
    seed_gate(
        os.environ["TEST_MIGRATION_DATABASE_URL"],
        output,
        seed=str(uuid4()),
        gateway_port=ports[0],
        endpoint_port=ports[1],
    )
    config_path = output / "gateway.json"
    config = json.loads(config_path.read_text())
    config["origin"] = "https://gate-trial.example.test"
    config_path.chmod(0o600)
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    fixture = json.loads((output / "fixture.json").read_text())
    running = DemoServices(output, {"ports": fixture["ports"]}, listeners=listeners)
    try:
        running.start("endpoint")
        # Times out (ValueError) unless the probe presents the tunnel host.
        running.start("gateway", readiness_host="gate-trial.example.test")
        with httpx.Client(trust_env=False, timeout=2) as client:
            refused = client.get(f"http://127.0.0.1:{ports[0]}/health/ready")
        assert refused.status_code == 400
    finally:
        running.stop("gateway")
        running.stop("endpoint")


def test_validation_harness_rejects_remote_before_creating_output(tmp_path, monkeypatch):
    from execbound_harness.validation_run import run_demo

    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://execbound_app:x@remote.example/execbound"
    )
    with pytest.raises(ValueError):
        run_demo(tmp_path / "private", tmp_path / "evidence")
    assert not (tmp_path / "evidence").exists()
