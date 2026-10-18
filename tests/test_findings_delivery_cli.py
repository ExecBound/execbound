# SPDX-License-Identifier: AGPL-3.0-only
"""`process --deliver` and `deliveries` (#31, FD13), on real PostgreSQL.

`--deliver` reads the destinations, the relay and the origin from `EXECBOUND_RUNTIME_CONFIG`
and nothing else. With `--all-tenants` each workspace's findings are routed and sent under that
workspace's own fence, as its scheduled actor; without `--deliver` nothing is sent, as MC21
pins. With `--config` they are sent as the configuration's administrator, for its workspace
alone. `deliveries` lists every row for an ADMIN.
"""

import argparse
import ast
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import assert_secret_free
from console_api_fixtures import every_log_line
from sqlalchemy import text
from test_approval_delivery_config import configuration, write
from test_monitor_process_all import Misfenced, run_process, workspace
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_monitoring_worker import receiver as receiver

from execbound.execution.scheduled import ScheduledActor
from execbound.monitoring import commands, models, store, worker
from execbound.monitoring.models import MonitorError, ObservationEvent
from execbound.surfaces import configuration as configuration_module
from execbound.surfaces.configuration import Destination


def hooks(admins, receiver):
    """One findings webhook per workspace, to the loopback receiver."""
    local, _ = receiver
    return [
        {
            "destination_id": "soc",
            "tenant_id": str(admin.tenant_id),
            "kind": "webhook",
            "url": local.url,
            "secret": local.secret,
            "classes": ["findings"],
        }
        for admin in admins
    ]


def private(tmp_path):
    """A directory for the private files, apart from `tmp_path` itself, where the loopback
    receiver stores each delivery it accepts as `<delivery id>.json`."""
    directory = tmp_path / "private"
    directory.mkdir(exist_ok=True)
    return directory


def rows_of(admin_engine, tenants):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT tenant_id, delivery_id, destination_id, state "
                    "FROM execbound.monitor_deliveries WHERE tenant_id = ANY(:ts)"
                ),
                {"ts": list(tenants)},
            ).mappings()
        ]


def test_fd13_all_tenants_deliver_sends_each_workspaces_findings(
    db, admin_engine, admins, receiver, tmp_path, monkeypatch, capsys
):
    clock = FixedClock(datetime.now(UTC))
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
    monkeypatch.setenv(
        "EXECBOUND_RUNTIME_CONFIG",
        str(write(private(tmp_path), configuration(*hooks(admins, receiver)))),
    )
    report = run_process(monkeypatch, capsys, "--all-tenants", "--deliver", "--limit", "50")
    assert (report["visited"], report["failed"]) == (2, 0)
    rows = rows_of(admin_engine, [admin.tenant_id for admin in admins])
    deliveries = [row for row in rows if row["destination_id"] == "soc"]
    assert deliveries and all(row["state"] == "DELIVERED" for row in deliveries)
    assert all(row["state"] == "ROUTED" for row in rows if row["destination_id"] is None)
    _, output = receiver
    received = {
        body["delivery_id"]: body["tenant_id"]
        for body in (json.loads(path.read_bytes()) for path in output.glob("*.json"))
    }
    assert received == {str(row["delivery_id"]): str(row["tenant_id"]) for row in deliveries}
    for admin in admins:
        mine = [row for row in deliveries if row["tenant_id"] == admin.tenant_id]
        outcome = report["tenants"][str(admin.tenant_id)]
        # Every finding routed and sent, none failed and none closed unsent.
        assert {key: outcome[key] for key in ("routed", "delivered", "failed", "closed")} == {
            "routed": len(mine),
            "delivered": len(mine),
            "failed": 0,
            "closed": 0,
        }


def test_fd13_all_tenants_deliver_sends_before_a_purge_that_fails(
    db, admin_engine, admins, receiver, tmp_path, monkeypatch, capsys
):
    """`process --all-tenants --deliver` sends each workspace's findings before the pass's last
    step, the purge of the directory audit observations no rule reads any more: a purge that
    fails, pass after pass, never keeps a finding from its destination. Each workspace is
    counted failed with the purge's code, and what it raised is delivered all the same."""
    clock = FixedClock(datetime.now(UTC))
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
    monkeypatch.setenv(
        "EXECBOUND_RUNTIME_CONFIG",
        str(write(private(tmp_path), configuration(*hooks(admins, receiver)))),
    )

    def failing(*args, **kwargs):
        raise MonitorError()

    monkeypatch.setattr(worker, "purge_audit_observations", failing)
    report = run_process(monkeypatch, capsys, "--all-tenants", "--deliver", "--limit", "50")
    assert (report["visited"], report["failed"]) == (2, 2)
    for admin in admins:
        assert report["tenants"][str(admin.tenant_id)] == {"skipped": "MONITOR_UNAVAILABLE"}
    rows = rows_of(admin_engine, [admin.tenant_id for admin in admins])
    deliveries = [row for row in rows if row["destination_id"] == "soc"]
    assert {row["tenant_id"] for row in deliveries} == {admin.tenant_id for admin in admins}
    assert all(row["state"] == "DELIVERED" for row in deliveries)
    _, output = receiver
    received = {
        body["delivery_id"]: body["tenant_id"]
        for body in (json.loads(path.read_bytes()) for path in output.glob("*.json"))
    }
    assert received == {str(row["delivery_id"]): str(row["tenant_id"]) for row in deliveries}


def test_fd13_all_tenants_without_deliver_reads_no_destination_and_sends_nothing(
    db, admin_engine, admins, receiver, tmp_path, monkeypatch, capsys
):
    """MC21's pass where the runtime configuration names a findings destination: without
    `--deliver` it is not read, so every intent waits unrouted and unattempted, and nothing is
    sent."""
    clock = FixedClock(datetime.now(UTC))
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
    monkeypatch.setenv(
        "EXECBOUND_RUNTIME_CONFIG",
        str(write(private(tmp_path), configuration(*hooks(admins, receiver)))),
    )
    report = run_process(monkeypatch, capsys, "--all-tenants", "--limit", "50")
    assert (report["visited"], report["failed"]) == (2, 0)
    rows = rows_of(admin_engine, [admin.tenant_id for admin in admins])
    assert rows and all((row["destination_id"], row["state"]) == (None, "PENDING") for row in rows)
    _, output = receiver
    assert list(output.glob("*.json")) == []
    for admin in admins:
        assert "routed" not in report["tenants"][str(admin.tenant_id)]


def test_fd13_each_workspace_is_routed_and_drained_under_its_own_fence(
    db, admin_engine, admins, receiver
):
    clock = FixedClock(datetime.now(UTC))
    first, second = admins
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
        store.evaluate_pending(db, admin, clock=clock)
    local, _ = receiver
    out = worker.Outbound(
        tuple(
            Destination(
                "soc", admin.tenant_id, local.url, local.secret, classes=frozenset({"findings"})
            )
            for admin in admins
        ),
        "http://127.0.0.1:8000",
    )
    misfenced = Misfenced(db, second.tenant_id)
    actor = ScheduledActor(first.tenant_id)
    for step in (
        lambda: worker.route_findings(misfenced, actor, out.destinations, clock=clock),
        lambda: worker.deliver_findings(misfenced, actor, out, clock=clock),
    ):
        with pytest.raises(MonitorError) as refused:
            step()
        assert refused.value.code == "INVALID_ADMIN"
    assert {row["state"] for row in rows_of(admin_engine, [second.tenant_id])} == {"PENDING"}
    assert worker.deliver_scheduled(db, second.tenant_id, out, clock=clock)["delivered"] >= 1


def test_fd13_the_scheduled_evaluation_sends_before_it_purges(
    db, admin_engine, admins, receiver, monkeypatch
):
    """Given an outbound, the scheduled evaluation routes and sends the workspace's findings
    before its last step, the purge of the directory audit observations no rule reads any more,
    as `process` does: `process --all-tenants --deliver` calls it so, and a purge that fails
    never keeps a finding from its destination. Its line counts both."""
    clock = FixedClock(datetime.now(UTC))
    first, _ = admins
    workspace(db, admin_engine, first, clock)
    local, _ = receiver
    out = worker.local_outbound(local, first.tenant_id, "http://127.0.0.1:8000")
    steps = []
    send, purge = worker.post_signed, worker.purge_audit_observations

    def sending(*args, **kwargs):
        steps.append("send")
        return send(*args, **kwargs)

    def purging(*args, **kwargs):
        steps.append("purge")
        return purge(*args, **kwargs)

    monkeypatch.setattr(worker, "post_signed", sending)
    monkeypatch.setattr(worker, "purge_audit_observations", purging)
    outcome = worker.evaluate_scheduled(db, first.tenant_id, clock=clock, outbound=out)
    assert steps[-1] == "purge" and steps.count("purge") == 1
    assert outcome["delivered"] == steps.count("send") >= 1
    assert set(outcome) == {
        "evaluated",
        "health_changes",
        "reach",
        "actions",
        "routed",
        "delivered",
        "failed",
        "closed",
        "purged",
    }


def test_fd13_config_deliver_sends_as_the_configurations_administrator(
    db, admin_engine, admins, seeded, receiver, tmp_path, monkeypatch, capsys
):
    clock = FixedClock(datetime.now(UTC))
    first, _ = admins
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
    monkeypatch.setenv(
        "EXECBOUND_RUNTIME_CONFIG",
        str(write(private(tmp_path), configuration(*hooks(admins, receiver)))),
    )
    monitor = private(tmp_path) / "monitor.json"
    monitor.write_text(
        json.dumps({"admin_token": seeded["tokens"][0], "gateway_port": 8000}), encoding="utf-8"
    )
    result = run_process(monkeypatch, capsys, "--config", str(monitor), "--deliver")
    # `process`'s five keys and Scout's audit retention's `purged` (ruling 8), and no other.
    assert set(result) == {"evaluated", "health_changes", "delivered", "reach", "actions", "purged"}
    assert result["delivered"] >= 1
    _, output = receiver
    assert {json.loads(path.read_bytes())["tenant_id"] for path in output.glob("*.json")} == {
        str(first.tenant_id)
    }


def test_fd13_deliver_is_refused_beside_deliver_local(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv", ["commands", "process", "--config", "m.json", "--deliver", "--deliver-local"]
    )
    with pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert "--deliver takes no --deliver-local" in capsys.readouterr().err


def test_fd13_deliver_local_is_refused_where_a_findings_destination_is_configured(
    db, admins, receiver, tmp_path, monkeypatch, capsys
):
    """A finding is routed once: a loopback run would take every pending one from the
    configured destinations (ruling 22). An approvals-only configuration leaves it alone."""
    monitor = private(tmp_path) / "monitor.json"
    monitor.write_text(
        json.dumps(
            {
                "admin_token": "not-a-credential",
                "receiver_port": 8321,
                "receiver_secret": "k" * 32,
                "gateway_port": 8000,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(
        sys, "argv", ["commands", "process", "--config", str(monitor), "--deliver-local"]
    )
    findings = hooks(admins, receiver)
    approvals = [{**item, "classes": ["approvals"]} for item in findings]
    reached: list[str] = []

    def authenticate(db, token):
        # The run got past the check: record it, then refuse as an unknown token would.
        reached.append(token)
        raise ValueError

    monkeypatch.setattr(commands, "authenticate", authenticate)

    def malformed():
        path = private(tmp_path) / "malformed.json"
        path.write_text("{not json", encoding="utf-8")
        return path

    for make, refused_here in (
        (lambda: write(private(tmp_path), configuration(*findings)), True),
        (lambda: write(private(tmp_path), configuration(*approvals)), False),
        # A runtime configuration that does not read leaves `--deliver-local` as it is.
        (lambda: private(tmp_path) / "absent.json", False),
        (malformed, False),
    ):
        monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(make()))
        reached.clear()
        with pytest.raises(SystemExit) as refused:
            commands.main()
        # Every run but the findings one gets past the check and is refused later, for its
        # token: the catch-all's sentence alone cannot tell that from a refusal at the check.
        assert refused.value.code == 2
        assert reached == ([] if refused_here else ["not-a-credential"])
        said = capsys.readouterr().err
        assert ("--deliver-local refused: FINDINGS_DESTINATIONS_CONFIGURED" in said) is (
            refused_here
        )
        assert ("Monitoring command unavailable" in said) is not refused_here


def test_fd13_deliver_needs_the_runtime_configuration(db, monkeypatch, capsys):
    monkeypatch.delenv("EXECBOUND_RUNTIME_CONFIG", raising=False)
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["commands", "process", "--all-tenants", "--deliver"])
    with pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert "--deliver needs EXECBOUND_RUNTIME_CONFIG" in capsys.readouterr().err


def test_fd13_deliver_reads_no_connector_and_loads_no_plugin(tmp_path, monkeypatch, admins):
    monkeypatch.setattr(
        configuration_module, "MockConnector", lambda *a, **k: pytest.fail("No connector")
    )
    monkeypatch.setattr(
        configuration_module, "load_plugins", lambda *a, **k: pytest.fail("No plugin")
    )
    soc = {
        "destination_id": "soc",
        "tenant_id": str(admins[0].tenant_id),
        "kind": "webhook",
        "url": "https://alerts.example.net/hook",
        "secret": "s" * 40,
        "classes": ["findings"],
    }
    outbound = configuration_module.read_outbound(write(tmp_path, configuration(soc)))
    assert [d.destination_id for d in outbound.destinations] == ["soc"]


def test_fd13_deliveries_lists_every_row_for_an_administrator(
    db, admin_engine, admins, seeded, receiver, tmp_path, monkeypatch, capsys
):
    clock = FixedClock(datetime.now(UTC))
    first, _ = admins
    workspace(db, admin_engine, first, clock)
    store.evaluate_pending(db, first, clock=clock)
    local, _ = receiver
    out = worker.Outbound(
        (
            Destination(
                "soc", first.tenant_id, local.url, local.secret, classes=frozenset({"findings"})
            ),
        ),
        "http://127.0.0.1:8000",
    )
    worker.route_findings(db, first, out.destinations, clock=clock)
    credential = tmp_path / "admin.token"
    credential.write_text(seeded["tokens"][0], encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for state, expected in ((None, {"ROUTED", "PENDING"}), ("ROUTED", {"ROUTED"})):
        argv = ["commands", "deliveries", "--credential-file", str(credential)]
        monkeypatch.setattr(sys, "argv", argv + (["--state", state] if state else []))
        commands.main()
        printed = capsys.readouterr().out
        listed = json.loads(printed)
        assert {row["state"] for row in listed} == expected
        # Identifiers, states, counts, times and codes: never a destination's URL or secret.
        assert all(set(row) == ROW_KEYS for row in listed)
        assert_secret_free(printed, known=(local.url, local.secret))


def test_fd13_deliveries_lists_the_newest_200_rows_newest_first(db, admin_engine, admins):
    """The listing is bounded as the console's lists are: the newest 200 rows, newest first, so
    the oldest of 201 deliveries and the intents written before them are left out."""
    clock = FixedClock(datetime.now(UTC))
    first, _ = admins
    workspace(db, admin_engine, first, clock)
    store.evaluate_pending(db, first, clock=clock)
    with admin_engine.begin() as conn:
        finding = conn.execute(
            text(
                "SELECT finding_id FROM execbound.monitor_findings WHERE tenant_id = :t "
                "ORDER BY finding_id LIMIT 1"
            ),
            {"t": first.tenant_id},
        ).scalar_one()
        written = clock.now() + timedelta(hours=1)
        for n in range(201):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_deliveries "
                    "(tenant_id, delivery_id, finding_id, destination_id, created_at, "
                    "next_attempt_at) VALUES (:t, gen_random_uuid(), :f, :d, :c, :c)"
                ),
                {
                    "t": first.tenant_id,
                    "f": finding,
                    "d": f"d{n}",
                    "c": written + timedelta(seconds=n),
                },
            )
    listed = worker.list_deliveries(db, first, clock=clock)
    assert [row.destination_id for row in listed] == [f"d{n}" for n in range(200, 0, -1)]


ROW_KEYS = {
    "delivery_id",
    "finding_id",
    "destination_id",
    "state",
    "attempts",
    "created_at",
    "next_attempt_at",
    "delivered_at",
    "last_error",
}


def test_fd13_deliveries_rechecks_the_administrator_and_names_only_a_delivery_state(
    db, admin_engine, admins
):
    """The listing is an administrator's: a credential revoked since it was read lists nothing.
    A state no delivery can be in is refused before anything is read."""
    first, _ = admins
    with pytest.raises(MonitorError) as refused:
        worker.list_deliveries(db, first, state="SENT")
    assert refused.value.code == "INVALID_STATE"
    # The command line offers exactly the states the listing takes.
    parser = commands.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    state = next(a for a in sub.choices["deliveries"]._actions if "--state" in a.option_strings)
    assert tuple(state.choices) == models.DELIVERY_STATES
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at = now() WHERE credential_id = :c"),
            {"c": first.credential_id},
        )
    with pytest.raises(MonitorError) as refused:
        worker.list_deliveries(db, first)
    assert refused.value.code == "INVALID_ADMIN"


@pytest.mark.parametrize("mode", ["all-tenants", "config"])
def test_fd13_a_runtime_configuration_broken_since_start_stops_no_evaluation(
    db, admin_engine, admins, seeded, receiver, tmp_path, monkeypatch, capsys, mode
):
    """The jobs service decides `--deliver` once, when it starts (ruling 21). A runtime
    configuration that read then and breaks later still stops no evaluation: the pass evaluates
    without delivery, then fails, so the job still shows the failure and findings are still
    raised. Nothing is routed or sent from the broken file."""
    clock = FixedClock(datetime.now(UTC))
    first, _ = admins
    path = write(private(tmp_path), configuration(*hooks(admins, receiver)))
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(path))
    monitor = private(tmp_path) / "monitor.json"
    monitor.write_text(
        json.dumps({"admin_token": seeded["tokens"][0], "gateway_port": 8000}), encoding="utf-8"
    )
    arguments = ["--all-tenants"] if mode == "all-tenants" else ["--config", str(monitor)]
    run_process(monkeypatch, capsys, *arguments, "--deliver")
    source = store.create_source(
        db,
        first,
        label="A later source",
        story_id="story-later",
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    store.ingest(
        db,
        source.token,
        ObservationEvent(
            event_id="event-later",
            story_id="story-later",
            occurred_at=clock.now(),
            kind="tool_result",
            action="identity.disable",
            target_ref="user-later",
            outcome="success",
        ),
        clock=clock,
    )
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["commands", "process", *arguments, "--deliver"])
    with every_log_line() as logged, pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert "Monitoring command unavailable" in capsys.readouterr().err
    # One line says the pass evaluated and the delivery file is what failed, after the pass's
    # own line, so an operator can tell it from an evaluation that failed, which logs no such
    # line, and from a dependency that did not answer.
    assert logged.holds("monitor.delivery_refused", "process", "INVALID_CONFIGURATION")
    lines = [json.loads(line) for line in logged.written().splitlines() if line.strip()]
    events = [line["event"] for line in lines]
    assert [
        {key: line.get(key) for key in ("level", "command", "code", "tenant_id")}
        for line in lines
        if line["event"] == "monitor.delivery_refused"
    ] == [
        {
            "level": "ERROR",
            "command": "process",
            "code": "INVALID_CONFIGURATION",
            # Run for one workspace, the line names it; a pass over every workspace names none.
            "tenant_id": str(first.tenant_id) if mode == "config" else None,
        }
    ]
    evaluated = "monitor.process_all" if mode == "all-tenants" else "monitor.processed"
    assert events.index(evaluated) < events.index("monitor.delivery_refused")
    assert "dependency.unavailable" not in events
    with admin_engine.connect() as conn:
        values = {"t": first.tenant_id, "s": source.source_id}
        pending = conn.execute(
            text(
                "SELECT count(*) FROM execbound.monitor_observations "
                "WHERE tenant_id = :t AND source_id = :s AND evaluation_state = 'PENDING'"
            ),
            values,
        ).scalar_one()
        raised = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT f.rule_version, d.destination_id, d.state "
                    "FROM execbound.monitor_findings f JOIN execbound.monitor_deliveries d "
                    "ON d.tenant_id = f.tenant_id AND d.finding_id = f.finding_id "
                    "WHERE f.tenant_id = :t AND f.source_id = :s"
                ),
                values,
            ).mappings()
        ]
    assert pending == 0
    assert raised == [
        {"rule_version": "sensitive-action.v2", "destination_id": None, "state": "PENDING"}
    ]


@pytest.mark.parametrize("mode", ["all-tenants", "config"])
def test_fd13_an_evaluation_that_fails_logs_no_delivery_refusal(
    db, admins, seeded, tmp_path, monkeypatch, capsys, mode
):
    """`monitor.delivery_refused` says the pass evaluated and only delivery was refused. An
    evaluation that stops the pass, here with an error no workspace's refusal contains, ends it
    first, so it writes no such line, even where the runtime configuration does not read
    either. A contained refusal is the next test's."""
    path = private(tmp_path) / "gateway.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(path))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monitor = private(tmp_path) / "monitor.json"
    monitor.write_text(
        json.dumps({"admin_token": seeded["tokens"][0], "gateway_port": 8000}), encoding="utf-8"
    )

    def failed(*args, **kwargs):
        raise RuntimeError("evaluation failed")

    if mode == "all-tenants":
        monkeypatch.setattr(worker, "evaluate_scheduled", failed)
        arguments = ["--all-tenants"]
    else:
        monkeypatch.setattr(worker, "process", failed)
        arguments = ["--config", str(monitor)]
    monkeypatch.setattr(sys, "argv", ["commands", "process", *arguments, "--deliver"])
    with every_log_line() as logged, pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert "Monitoring command unavailable" in capsys.readouterr().err
    events = [json.loads(line)["event"] for line in logged.written().splitlines() if line.strip()]
    assert "monitor.delivery_refused" not in events
    assert not {"monitor.process_all", "monitor.processed"} & set(events)


def test_fd13_a_contained_workspace_refusal_still_logs_the_broken_file(
    db, admins, tmp_path, monkeypatch, capsys
):
    """Only an evaluation that stops the pass writes no `monitor.delivery_refused`. Under
    `--all-tenants`, one workspace whose evaluation is refused with a `MonitorError`, a
    `ValueError`, is contained like any refusal: the pass goes on, counts it in
    `monitor.process_all`'s `failed`, and the broken runtime configuration's line follows."""
    path = private(tmp_path) / "gateway.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(path))
    first, _ = admins
    evaluate = worker.evaluate_scheduled

    def refused_in_one(db, tenant, **kwargs):
        if tenant == first.tenant_id:
            raise MonitorError("INVALID_CLOCK")
        return evaluate(db, tenant, **kwargs)

    monkeypatch.setattr(worker, "evaluate_scheduled", refused_in_one)
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["commands", "process", "--all-tenants", "--deliver"])
    with every_log_line() as logged, pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert "Monitoring command unavailable" in capsys.readouterr().err
    lines = [json.loads(line) for line in logged.written().splitlines() if line.strip()]
    events = [line["event"] for line in lines]
    [summary] = [line for line in lines if line["event"] == "monitor.process_all"]
    assert summary["failed"] == 1 and summary["visited"] >= 2
    assert events.count("monitor.delivery_refused") == 1
    assert events.index("monitor.process_all") < events.index("monitor.delivery_refused")


def test_the_commands_import_the_notifier_in_a_function_and_parse_without_the_worker():
    """`execbound.notifications` is one end of an import cycle: imported on its own it raises
    `ImportError`, and it imports cleanly only once `execbound.execution` has loaded it. The
    monitoring commands import it where they use it, never at the top, so importing them never
    depends on what came before. Building the parser, as the command-line reference does, never
    loads the worker either."""
    tree = ast.parse(Path(commands.__file__).read_text(encoding="utf-8"))
    imported = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)} | {
        alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names
    }
    assert "execbound.notifications" not in imported
    script = (
        "import sys\n"
        "from execbound.monitoring import commands\n"
        "commands.build_parser()\n"
        "print('execbound.monitoring.worker' in sys.modules)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True, timeout=60
    )
    assert result.stdout.strip() == "False"
