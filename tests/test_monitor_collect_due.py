# SPDX-License-Identifier: AGPL-3.0-only
"""MC7: collecting due monitoring connections on a schedule with no workspace credential (#678).

Real PostgreSQL, the fake Tines API and the fake Graph API. `collect-due --all-tenants` visits
every active workspace as its scheduled actor, collects each due connection whose key file the
collector holds inside that connection's lease, and counts the rest. One workspace's refusal is
its own line and never the exit code; its output carries counts and codes, never a key. The
operator's own `collect-tines` and `collect-entra` take the same lease.
"""

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sample_fixtures import empty_workspace
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_scout_run import detailed_scenario, principal
from test_tines_collection import scenario

from execbound.monitoring import collection, commands, due, graph, store
from execbound_harness import fake_graph, fake_tines
from execbound_harness.fake_graph import CLIENT, DIRECTORY, SECRET
from execbound_harness.fake_tines import BASE_URL

pytestmark = pytest.mark.integration

# A key no output, log line or table may ever repeat.
SENTINEL = "SENTINEL-collect-due-key-7f3a9c"


class Routing(httpx.BaseTransport):
    """The fake Tines tenant and the fake directory behind one client, as the collector's one
    client reaches both; each request may move an injected monotonic clock on."""

    def __init__(self, tines, directory, ticks=None):
        self.tines = fake_tines.transport(tines)
        self.directory = fake_graph.transport(directory)
        self.ticks = ticks

    def handle_request(self, request):
        if self.ticks is not None:
            self.ticks["now"] += 60.0
        if request.url.host == "fixture.tines.com":
            return self.tines.handle_request(request)
        return self.directory.handle_request(request)


def connect_tines(db, admin, clock, key=SENTINEL):
    return store.create_connection(
        db,
        admin,
        label="Synthetic Tines tenant",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(key),
        clock=clock,
    )


def connect_entra(db, admin, clock):
    return store.create_connection(
        db,
        admin,
        label="Synthetic directory",
        base_url=graph.GRAPH_ORIGIN,
        key_fingerprint=graph.fingerprint(SECRET),
        kind="entra_agent_id",
        directory_ref=DIRECTORY,
        client_ref=CLIENT,
        clock=clock,
    )


def key_file(directory, connection, *, entra=False, key=SENTINEL):
    directory.mkdir(exist_ok=True)
    path = directory / f"{connection}.env"
    path.write_text(
        f"ENTRA_DIRECTORY_ID={DIRECTORY}\nENTRA_CLIENT_ID={CLIENT}\nENTRA_CLIENT_SECRET={SECRET}\n"
        if entra
        else f"TINES_BASE_URL={BASE_URL}\nTINES_API_KEY={key}\n",
        encoding="utf-8",
    )
    return path


def connection_row(admin_engine, tenant, connection):
    with admin_engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": connection},
            )
            .mappings()
            .one()
        )


@pytest.fixture
def fakes(clock):
    with (
        fake_tines.serving(scenario(clock.now())) as tines,
        fake_graph.serving(detailed_scenario()) as directory,
    ):
        yield tines, directory


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def cli(monkeypatch, capsys, fakes, *arguments, ticks=None):
    tines, directory = fakes
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(
        commands,
        "_http_client",
        lambda: httpx.Client(
            transport=Routing(tines, directory, ticks), trust_env=False, follow_redirects=False
        ),
    )
    monkeypatch.setattr(sys, "argv", ["commands", *arguments])
    commands.main()
    return capsys.readouterr()


def test_mc7_one_pass_collects_each_workspace_on_its_default_intervals(
    db, admin_engine, admins, fakes, clock, tmp_path, monkeypatch, capsys, caplog
):
    first, second = admins
    tines = connect_tines(db, first, clock)
    entra = connect_entra(db, second, clock)
    files = tmp_path / "key-files"
    key_file(files, tines)
    key_file(files, entra, entra=True)
    dormant = empty_workspace(admin_engine, db)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": dormant.tenant_id},
        )
    caplog.set_level("INFO", logger="execbound")
    out = cli(monkeypatch, capsys, fakes, "collect-due", "--all-tenants", "--key-files", str(files))
    report = json.loads(out.out)
    assert (report["visited"], report["failed"], report["inactive"]) == (2, 0, 1)
    assert report["tenants"] == {
        str(first.tenant_id): {
            "collected": 1,
            "no_key_file": 0,
            "deferred": 0,
            "not_reached": 0,
            "busy": 0,
            "failed": 0,
            "delta": 0,
            "delta_failed": 0,
            "audit_failed": 0,
            "audit_backlog": 0,
            "audit_bounded": 0,
        },
        str(second.tenant_id): {
            "collected": 1,
            "no_key_file": 0,
            "deferred": 0,
            "not_reached": 0,
            "busy": 0,
            "failed": 0,
            "delta": 0,
            "delta_failed": 0,
            "audit_failed": 0,
            "audit_backlog": 0,
            "audit_bounded": 0,
        },
    }
    for admin, connection in ((first, tines), (second, entra)):
        row = connection_row(admin_engine, admin.tenant_id, connection)
        assert row["last_outcome"] == "COMPLETE"
        assert (row["collecting_until"], row["collecting_lease"]) == (None, None)
        # Collected now, so not due again until its kind's default interval has passed.
        assert not due.is_due(row, datetime.now(UTC))
    # Counts and codes only: no key, secret or token anywhere the pass writes.
    for text_out in (out.out, out.err, caplog.text):
        assert SENTINEL not in text_out and SECRET not in text_out
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.principals WHERE kind = 'SYSTEM'")
            ).scalar_one()
            == 0
        )
    # A second pass inside the interval collects nothing; the directory, which now holds a
    # delta link, gets a delta pass between its full collections (#355).
    pass_again = ("collect-due", "--all-tenants", "--key-files", str(files))
    out = cli(monkeypatch, capsys, fakes, *pass_again)
    again = json.loads(out.out)
    assert set(again["tenants"]) == {str(second.tenant_id)}
    assert again["tenants"][str(second.tenant_id)]["collected"] == 0
    assert again["tenants"][str(second.tenant_id)]["delta"] == 1

    # The log line counts the delta passes too, so one that fails is seen where the pass is.
    def logged(err):
        (line,) = [
            record
            for record in (json.loads(line) for line in err.splitlines() if line[:1] == "{")
            if record["event"] == "monitor.collect_due"
        ]
        return {
            key: line[key]
            for key in (
                "count",
                "delta",
                "delta_failed",
                "audit_failed",
                "audit_backlog",
                "audit_bounded",
            )
        }

    quiet = {"audit_failed": 0, "audit_backlog": 0, "audit_bounded": 0}
    assert logged(out.err) == {"count": 0, "delta": 1, "delta_failed": 0, **quiet}
    # Graph refuses the next delta pass: the pass records nothing on the connection, and the
    # log line is where it is seen.
    _, directory = fakes
    directory.scenario.status = {"delta": 429}
    out = cli(monkeypatch, capsys, fakes, *pass_again)
    assert json.loads(out.out)["tenants"][str(second.tenant_id)]["delta_failed"] == 1
    assert logged(out.err) == {"count": 0, "delta": 0, "delta_failed": 1, **quiet}
    # Nor does a refused read of the directory's audit log record anything on the connection,
    # so the log line is where it is seen too (#355).
    directory.scenario.status = {}
    directory.scenario.audit_status = 429
    out = cli(monkeypatch, capsys, fakes, *pass_again)
    assert json.loads(out.out)["tenants"][str(second.tenant_id)]["audit_failed"] == 1
    assert logged(out.err) == {
        "count": 0,
        "delta": 1,
        "delta_failed": 0,
        "audit_failed": 1,
        "audit_backlog": 0,
        "audit_bounded": 0,
    }
    # And a read that stops at its pages short of catching up: two days behind, one entry a
    # page, a person's change every hour.
    behind = datetime.now(UTC) - timedelta(days=2)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET audit_cursor = :c "
                "WHERE connection_id = :i"
            ),
            {"c": behind.replace(microsecond=0), "i": entra},
        )
    directory.scenario.audit_status = None
    directory.scenario.max_top = 1
    directory.scenario.audits = [
        {
            "id": f"Directory_{uuid4()}",
            "activityDateTime": (behind + timedelta(hours=hour)).isoformat(),
            "activityDisplayName": "Update user",
            "loggedByService": "Core Directory",
            "result": "success",
            "initiatedBy": {"user": {"id": str(uuid4())}, "app": None},
            "targetResources": [],
        }
        for hour in range(1, 12)
    ]
    out = cli(monkeypatch, capsys, fakes, *pass_again)
    assert json.loads(out.out)["tenants"][str(second.tenant_id)]["audit_backlog"] == 1
    assert logged(out.err) == {
        "count": 0,
        "delta": 1,
        "delta_failed": 0,
        "audit_failed": 0,
        "audit_backlog": 1,
        "audit_bounded": 0,
    }
    # And a read that meets the connection's observation bound: no refusal, counted apart.
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 0)
    directory.scenario.max_top = 100
    directory.scenario.audits = [
        {
            "id": f"Directory_{uuid4()}",
            "activityDateTime": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            "activityDisplayName": "Disable account",
            "loggedByService": "Core Directory",
            "result": "success",
            "initiatedBy": {"app": {"servicePrincipalId": str(uuid4())}, "user": None},
            "targetResources": [{"id": str(uuid4()), "type": "User", "modifiedProperties": []}],
        }
    ]
    out = cli(monkeypatch, capsys, fakes, *pass_again)
    assert json.loads(out.out)["tenants"][str(second.tenant_id)]["audit_bounded"] == 1
    assert logged(out.err) == {
        "count": 0,
        "delta": 1,
        "delta_failed": 0,
        "audit_failed": 0,
        "audit_backlog": 0,
        "audit_bounded": 1,
    }


def test_mc7_a_connection_without_its_key_file_is_counted_and_left_alone(
    db, admin_engine, admins, fakes, clock, tmp_path
):
    tines_server, directory = fakes
    connection = connect_tines(db, admins[0], clock)
    before = connection_row(admin_engine, admins[0].tenant_id, connection)
    with httpx.Client(transport=Routing(tines_server, directory), trust_env=False) as http:
        for files in (tmp_path / "absent", None):
            report = due.collect_due(db, key_files=files, client=http, clock=clock)
            outcome = report["tenants"][str(admins[0].tenant_id)]
            assert (outcome["no_key_file"], outcome["collected"]) == (1, 0)
    # The file may be on an operator's own host: nothing is recorded, nothing is requested.
    assert tines_server.requests == [] and directory.requests == []
    assert connection_row(admin_engine, admins[0].tenant_id, connection) == before


def test_mc7_the_per_tenant_cap_defers_a_due_connection_to_the_next_pass(
    db, admin_engine, admins, fakes, clock, tmp_path
):
    tines_server, directory = fakes
    admin = admins[0]
    tines = connect_tines(db, admin, clock)
    entra = connect_entra(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, tines)
    key_file(files, entra, entra=True)
    with httpx.Client(transport=Routing(tines_server, directory), trust_env=False) as http:
        first = due.collect_due(db, key_files=files, per_tenant=1, client=http, clock=clock)
        outcome = first["tenants"][str(admin.tenant_id)]
        assert (outcome["collected"], outcome["deferred"]) == (1, 1)
        outcomes = [
            connection_row(admin_engine, admin.tenant_id, connection)["last_outcome"]
            for connection in (tines, entra)
        ]
        assert sorted(outcomes, key=str) == ["COMPLETE", None]
        # The other waits for the next pass, where it is the one due.
        second = due.collect_due(db, key_files=files, per_tenant=1, client=http, clock=clock)
        assert second["tenants"][str(admin.tenant_id)]["collected"] == 1
    for connection in (tines, entra):
        assert connection_row(admin_engine, admin.tenant_id, connection)["last_outcome"] == (
            "COMPLETE"
        )


def test_mc7_the_budget_stops_starting_connections(
    db, admin_engine, admins, fakes, clock, tmp_path
):
    tines_server, directory = fakes
    admin = admins[0]
    tines = connect_tines(db, admin, clock)
    entra = connect_entra(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, tines)
    key_file(files, entra, entra=True)
    ticks = {"now": 0.0}
    with httpx.Client(transport=Routing(tines_server, directory, ticks), trust_env=False) as http:
        report = due.collect_due(
            db,
            key_files=files,
            budget_seconds=30,
            client=http,
            clock=clock,
            monotonic=lambda: ticks["now"],
        )
    outcome = report["tenants"][str(admin.tenant_id)]
    # The first run's requests spent the budget, so the second never started: one platform
    # was asked for nothing, and one connection records no run. Both were due since the same
    # instant, so which went first is not fixed.
    assert (outcome["collected"], outcome["not_reached"]) == (1, 1)
    assert [tines_server.requests == [], directory.requests == []].count(True) == 1
    outcomes = [
        connection_row(admin_engine, admin.tenant_id, connection)["last_outcome"]
        for connection in (tines, entra)
    ]
    assert sorted(outcomes, key=str) == ["COMPLETE", None]


@pytest.mark.parametrize("bound", ["cap", "budget", "neither"])
def test_mc7_a_delta_pass_starts_only_within_the_cap_and_budget_the_due_runs_left(
    db, admin_engine, admins, fakes, clock, tmp_path, bound
):
    """The delta passes come after the due collections, within the same per-workspace cap and
    budget (#355): once the due collections have started as many runs as the cap allows, or
    spent the budget, no delta pass starts, and the directory's changes wait for the next pass.
    With room left, the same directory gets its pass."""
    tines_server, directory = fakes
    admin = admins[0]
    tines = connect_tines(db, admin, clock)
    entra = connect_entra(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, tines)
    key_file(files, entra, entra=True)
    with httpx.Client(transport=Routing(tines_server, directory), trust_env=False) as http:
        first = due.collect_due(db, key_files=files, client=http, clock=clock)
    assert first["tenants"][str(admin.tenant_id)]["collected"] == 2
    before = connection_row(admin_engine, admin.tenant_id, entra)
    assert before["delta_link"] is not None and before["baseline_at"] is not None
    # Tines is due again inside the directory's interval, and the directory has a change.
    clock.value += timedelta(seconds=due.DEFAULT_ACTIVITY)
    changed = principal(9)
    directory.scenario.delta = [changed]
    # Every request moves the pass's clock a minute on, so the due run spends the budget.
    ticks = {"now": 0.0}
    with httpx.Client(
        transport=Routing(tines_server, directory, ticks if bound == "budget" else None),
        trust_env=False,
    ) as http:
        report = due.collect_due(
            db,
            key_files=files,
            client=http,
            clock=clock,
            per_tenant=1 if bound == "cap" else due.PER_TENANT,
            budget_seconds=30 if bound == "budget" else due.BUDGET_SECONDS,
            **({"monotonic": lambda: ticks["now"]} if bound == "budget" else {}),
        )
    outcome = report["tenants"][str(admin.tenant_id)]
    ran = bound == "neither"
    assert (outcome["collected"], outcome["delta"], outcome["delta_failed"]) == (1, int(ran), 0)
    after = connection_row(admin_engine, admin.tenant_id, entra)
    assert (after["delta_at"] != before["delta_at"]) is ran
    with admin_engine.connect() as conn:
        stored = conn.execute(
            text(
                "SELECT count(*) FROM execbound.monitor_agents "
                "WHERE tenant_id = :t AND platform_ref = :r"
            ),
            {"t": admin.tenant_id, "r": changed["id"]},
        ).scalar_one()
    assert stored == int(ran)


def test_mc7_a_key_file_that_is_not_the_registered_key_is_recorded_and_never_sent(
    db, admin_engine, admins, fakes, clock, tmp_path
):
    tines_server, directory = fakes
    admin = admins[0]
    connection = connect_tines(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection, key="a-different-key")
    with httpx.Client(transport=Routing(tines_server, directory), trust_env=False) as http:
        report = due.collect_due(db, key_files=files, client=http, clock=clock)
    # Recorded on the connection, and counted as a failure: nothing was collected.
    counts = report["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["failed"]) == (0, 1)
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert (row["last_outcome"], row["last_error_code"], row["health_state"]) == (
        "ERROR",
        "KEY_MISMATCH",
        "ERROR",
    )
    assert tines_server.requests == []
    store.revoke_connection(db, admin, connection)
    connection = connect_tines(db, admin, clock)
    (files / f"{connection}.env").write_text("not a key file at all\n", encoding="utf-8")
    with httpx.Client(transport=Routing(tines_server, directory), trust_env=False) as http:
        report = due.collect_due(db, key_files=files, client=http, clock=clock)
    counts = report["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["failed"]) == (0, 1)
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "KEY_FILE_INVALID")
    assert tines_server.requests == []


def test_mc7_an_operator_run_collects_its_own_workspace_as_its_administrator(
    db, admin_engine, admins, seeded, fakes, clock, tmp_path, monkeypatch, capsys
):
    admin = admins[0]
    connection = connect_tines(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection)
    credential = tmp_path / "admin.token"
    credential.write_text(seeded["tokens"][0] + "\n", encoding="utf-8")
    out = cli(
        monkeypatch,
        capsys,
        fakes,
        "collect-due",
        "--tenant",
        str(admin.tenant_id),
        "--credential-file",
        str(credential),
        "--key-files",
        str(files),
    )
    assert json.loads(out.out)["collected"] == 1
    assert SENTINEL not in out.out + out.err
    assert connection_row(admin_engine, admin.tenant_id, connection)["last_outcome"] == "COMPLETE"


def test_mc7_an_operator_run_refuses_a_token_that_is_not_its_workspaces_administrator(
    db, admin_engine, seeded, fakes, clock, tmp_path, monkeypatch, capsys
):
    # The seeded principals are agents: an agent's token is never an operator's.
    tenant = seeded["tenants"][0]
    credential = tmp_path / "agent.token"
    credential.write_text(seeded["tokens"][0] + "\n", encoding="utf-8")
    for named in (tenant, seeded["tenants"][1]):
        with pytest.raises(SystemExit) as refused:
            cli(
                monkeypatch,
                capsys,
                fakes,
                "collect-due",
                "--tenant",
                str(named),
                "--credential-file",
                str(credential),
            )
        assert refused.value.code == 2
    tines_server, directory = fakes
    assert tines_server.requests == [] and directory.requests == []


@pytest.mark.parametrize("command", ["collect-tines", "collect-entra"])
def test_mc7_an_operator_collection_waits_for_no_one_and_overlaps_no_one(
    db, admin_engine, admins, seeded, fakes, clock, tmp_path, monkeypatch, capsys, command
):
    admin = admins[0]
    entra = command == "collect-entra"
    connection = connect_entra(db, admin, clock) if entra else connect_tines(db, admin, clock)
    path = key_file(tmp_path, connection, entra=entra)
    credential = tmp_path / "admin.token"
    credential.write_text(seeded["tokens"][0] + "\n", encoding="utf-8")
    held = uuid4()
    assert due.claim(db, admin, connection, held)
    before = connection_row(admin_engine, admin.tenant_id, connection)
    arguments = (
        command,
        "--credential-file",
        str(credential),
        "--connection",
        str(connection),
        "--key-file",
        str(path),
    )
    with pytest.raises(SystemExit) as refused:
        cli(monkeypatch, capsys, fakes, *arguments)
    assert refused.value.code == 2
    assert "Collection already running for that connection." in capsys.readouterr().err
    assert connection_row(admin_engine, admin.tenant_id, connection) == before
    tines_server, directory = fakes
    assert tines_server.requests == [] and directory.requests == []
    # Once the run holding it returns the lease, the operator's run collects, and returns it.
    due.release(db, admin, connection, held)
    out = cli(monkeypatch, capsys, fakes, *arguments)
    assert json.loads(out.out)["outcome"] == "COMPLETE"
    assert SENTINEL not in out.out + out.err and SECRET not in out.out + out.err
    after = connection_row(admin_engine, admin.tenant_id, connection)
    assert (after["collecting_until"], after["collecting_lease"]) == (None, None)


@pytest.mark.parametrize(
    "arguments,message",
    [
        (["collect-due"], "give --all-tenants or both --tenant and --credential-file"),
        (
            ["collect-due", "--all-tenants", "--tenant", str(uuid4())],
            "--all-tenants takes no --tenant or --credential-file",
        ),
        (
            ["collect-due", "--all-tenants", "--credential-file", "x"],
            "--all-tenants takes no --tenant or --credential-file",
        ),
        (["collect-due", "--tenant", str(uuid4())], "give --all-tenants or both"),
        (["collect-due", "--all-tenants", "--per-tenant", "0"], "--per-tenant must be 1 to 20"),
        (["collect-due", "--all-tenants", "--per-tenant", "21"], "--per-tenant must be 1 to 20"),
        (
            ["collect-due", "--all-tenants", "--budget-seconds", "0"],
            "--budget-seconds must be 1 to 3600",
        ),
    ],
)
def test_mc7_collect_due_refuses_its_arguments_before_anything_else(
    arguments, message, monkeypatch, capsys
):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["commands", *arguments])
    with pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert message in capsys.readouterr().err


def consented_connection(admin_engine, admin, clock, *, client=CLIENT):
    """A directory an administrator consented to, as `admin_complete_consent` leaves one, written
    by the owner: no key, the consent, and registered a day ago so it is due."""
    from space_fixtures import default_space

    connection = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(admin.tenant_id)},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
                "base_url, key_fingerprint, created_at, created_by, kind, directory_ref, "
                "client_ref, space_id, credential_mode, consented_at, consented_by) "
                "VALUES (:t, :c, 'Consented directory', :u, NULL, :at, :p, 'entra_agent_id', "
                ":dir, :client, :s, 'platform_app', :at, :p)"
            ),
            {
                "t": admin.tenant_id,
                "c": connection,
                "u": graph.GRAPH_ORIGIN,
                "at": clock.now() - timedelta(days=1),
                "p": admin.principal_id,
                "dir": DIRECTORY,
                "client": client,
                "s": default_space(conn, admin.tenant_id),
            },
        )
    return connection


@pytest.fixture
def platform(tmp_path, fakes):
    """The platform app's credential file, its certificate registered with the fake directory."""
    credential = fake_graph.platform_app()
    fakes[1].scenario.certificate = credential["certificate_pem"]
    path = tmp_path / "scout-app.json"
    path.write_text(json.dumps(credential), encoding="utf-8")
    return path, credential


def test_mc7_collect_due_collects_a_consented_directory_with_the_platform_app(
    db, admin_engine, admins, fakes, clock, platform, monkeypatch, capsys, caplog
):
    path, credential = platform
    admin = admins[0]
    connection = consented_connection(admin_engine, admin, clock)
    caplog.set_level("INFO", logger="execbound")
    out = cli(
        monkeypatch, capsys, fakes, "collect-due", "--all-tenants", "--platform-app", str(path)
    )
    report = json.loads(out.out)
    assert report["tenants"][str(admin.tenant_id)]["collected"] == 1
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert (row["last_outcome"], row["last_error_code"]) == ("COMPLETE", None)
    # It authenticated with the certificate, once, for the consenting directory.
    _, directory = fakes
    assert [claims["iss"] for claims in directory.assertions] == [CLIENT]
    for text_out in (out.out, out.err, caplog.text):
        assert credential["private_key_pem"][40:80] not in text_out


def test_mc3_a_consented_directory_for_another_app_records_client_mismatch_and_asks_nothing(
    db, admin_engine, admins, fakes, clock, platform, monkeypatch, capsys
):
    path, _ = platform
    admin = admins[0]
    connection = consented_connection(
        admin_engine, admin, clock, client="99999999-8888-7777-6666-555555555555"
    )
    out = cli(
        monkeypatch, capsys, fakes, "collect-due", "--all-tenants", "--platform-app", str(path)
    )
    assert json.loads(out.out)["tenants"][str(admin.tenant_id)]["failed"] == 1
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "CLIENT_MISMATCH")
    # No token request, and nothing else, reached the directory.
    assert fakes[1].requests == []


def test_mc3_without_the_platform_app_a_consented_directory_records_why_and_asks_nothing(
    db, admin_engine, admins, fakes, clock, platform, tmp_path, monkeypatch, capsys
):
    path, _ = platform
    admin = admins[0]
    connection = consented_connection(admin_engine, admin, clock)
    for arguments in ((), ("--platform-app", str(tmp_path / "not-yet" / "scout-app.json"))):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET last_run_at = NULL "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": admin.tenant_id, "c": connection},
            )
        out = cli(monkeypatch, capsys, fakes, "collect-due", "--all-tenants", *arguments)
        assert json.loads(out.out)["tenants"][str(admin.tenant_id)]["failed"] == 1, arguments
        row = connection_row(admin_engine, admin.tenant_id, connection)
        assert row["last_error_code"] == "COLLECTOR_KEY_UNAVAILABLE", arguments
    assert fakes[1].requests == []
    # A file that is not the platform app's credential stops the run before any workspace.
    broken = tmp_path / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as refused:
        cli(
            monkeypatch,
            capsys,
            fakes,
            "collect-due",
            "--all-tenants",
            "--platform-app",
            str(broken),
        )
    assert refused.value.code == 2
    assert fakes[1].requests == []


@pytest.mark.parametrize("client", [CLIENT, "99999999-8888-7777-6666-555555555555"])
def test_mc3_a_run_itself_reads_a_consented_directory_only_with_the_app_it_names(
    db, admin_engine, admins, fakes, clock, platform, client
):
    """The run checks the row's client id against the app it was given, whoever called it,
    and before any request; a run given no app, or an operator's secret, reads nothing."""
    _, credential = platform
    app = graph.PlatformApp.from_text(json.dumps(credential))
    admin = admins[0]
    connection = consented_connection(admin_engine, admin, clock, client=client)
    tines, directory = fakes
    with httpx.Client(transport=Routing(tines, directory), trust_env=False) as http:
        for credentials, code in (
            ({"app": app}, None if client == CLIENT else "CLIENT_MISMATCH"),
            ({"client_secret": SECRET}, "COLLECTOR_KEY_UNAVAILABLE"),
            ({}, "COLLECTOR_KEY_UNAVAILABLE"),
        ):
            if code is None:
                assert (
                    graph.run(db, admin, connection_id=connection, client=http, **credentials)[
                        "outcome"
                    ]
                    == "COMPLETE"
                )
                continue
            before = len(directory.requests)
            with pytest.raises(graph.GraphError) as refused:
                graph.run(db, admin, connection_id=connection, client=http, **credentials)
            assert refused.value.code == code
            assert len(directory.requests) == before
