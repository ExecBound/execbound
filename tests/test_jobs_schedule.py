# SPDX-License-Identifier: AGPL-3.0-only
"""The jobs service: one tick, one run, whichever replica gets there first.

The claim on #411 is that a second jobs
replica never runs a job twice. A lock released when the run finishes would not give that: it
would stop two replicas running a job at the same moment and leave the second free to run the
same interval a second later. So the lock is taken for the tick and held for the rest of it,
and that is what these read.

Nothing here runs a real job. The commands are the ones the runbook documents and are covered
where they live; what is under test is the scheduling, the lock and what happens when the
credential a job needs is not there yet.
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

import pytest
from conftest import local_test_url

from execbound import install, schedule

pytestmark = pytest.mark.integration

FAST = (
    schedule.Job("recover", 77_001, 900, schedule.JOBS_FILE),
    schedule.Job("notify", 77_002, 120, schedule.JOBS_FILE),
    schedule.Job("monitor-process", 77_003, 300, schedule.MONITOR_FILE),
)


@pytest.fixture
def state(tmp_path):
    """A state directory holding what quickstart would have written."""
    (tmp_path / schedule.JOBS_FILE).write_text('{"tenant": "token"}', encoding="utf-8")
    (tmp_path / schedule.MONITOR_FILE).write_text('{"admin_token": "token"}', encoding="utf-8")
    return tmp_path


@pytest.fixture
def engine():
    engine = schedule.engine_for(local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app"))
    yield engine
    engine.dispose()


@pytest.fixture
def ran(monkeypatch):
    """Every job the scheduler starts, with a trivial process standing in for the command."""
    started: list[str] = []

    def fake(job, state, *, limit=50, collector=None, checkpoints=None):
        started.append(job.name)
        return [sys.executable, "-c", "pass"]

    monkeypatch.setattr(schedule, "argv", fake)
    return started


def worker(engine, state, **changes):
    return schedule.Scheduler(engine, state=state, jobs=FAST, **changes)


def test_every_replica_computes_the_same_tick():
    """A tick is derived from the clock alone, so two processes agree without talking.

    `hash()` would not do: it is randomized per process, and each replica would then take a
    lock the other never contends for and run every interval itself.
    """
    job = FAST[0]
    assert schedule.tick(job, 1_800_000_000.0) == schedule.tick(job, 1_800_000_899.0)
    assert schedule.tick(job, 1_800_000_900.0) == schedule.tick(job, 1_800_000_000.0) + 1
    assert 0 < schedule.tick(job, 1_800_000_000.0) <= schedule.INT32


def test_a_first_pass_runs_every_job_once(engine, state, ran):
    """A jobs service that started would sweep in a quarter of an hour, not immediately.

    Every job is due at start, which is also what makes the fresh-machine job's check
    possible: after quickstart the three of them run within a cycle rather than on the hour.
    """
    scheduler = worker(engine, state)
    try:
        outcomes = scheduler.cycle()
    finally:
        scheduler.close()
    assert set(outcomes) == {job.name for job in FAST}
    assert set(outcomes.values()) == {0}
    assert sorted(ran) == sorted(job.name for job in FAST)


def test_a_second_pass_inside_the_same_tick_runs_nothing(engine, state, ran):
    """Both passes read one instant: on the wall clock, a tick boundary between them (two
    minutes for `notify` here) would make the second pass's run correct and this test fail."""
    now = time.time()
    scheduler = worker(engine, state)
    try:
        scheduler.cycle(now)
        assert scheduler.cycle(now) == {}
    finally:
        scheduler.close()
    assert len(ran) == len(FAST)


def test_a_second_replica_cannot_take_a_tick_the_first_holds(engine, state, ran):
    """The whole guarantee. The second replica runs nothing while the first holds the tick.

    Both read one instant, so the second asks for the tick the first holds rather than the
    next one, which a slow first pass could otherwise reach on the wall clock."""
    now = time.time()
    first, second = worker(engine, state), worker(engine, state)
    try:
        assert set(first.cycle(now)) == {job.name for job in FAST}
        assert second.cycle(now) == {}
    finally:
        first.close()
        second.close()
    assert sorted(ran) == sorted(job.name for job in FAST)


def test_a_replica_that_stops_hands_its_ticks_on(engine, state, ran):
    """A lock lives in the session holding it, so a replica that dies frees its ticks.

    That is the behaviour wanted rather than a hole: a jobs service that crashed mid-tick
    must not leave that interval unrun until the process comes back.
    """
    first = worker(engine, state)
    first.cycle()
    first.close()
    second = worker(engine, state)
    try:
        assert set(second.cycle()) == {job.name for job in FAST}
    finally:
        second.close()
    assert len(ran) == 2 * len(FAST)


@pytest.fixture
def logged(caplog):
    """The events the scheduler logs. `log_event` writes nothing to a logger with no handler."""
    logger = logging.getLogger("execbound")
    handler = logging.NullHandler()
    logger.addHandler(handler)
    try:
        with caplog.at_level(logging.INFO, logger="execbound"):
            yield lambda: [
                record.execbound for record in caplog.records if hasattr(record, "execbound")
            ]
    finally:
        logger.removeHandler(handler)


def end_session(engine, connection):
    """What a PostgreSQL restart does to every session: the server ends it, and the locks it
    held go with it. The runtime role may end its own role's sessions, so no owner is needed;
    the wait is for the server to have finished, not a guess at how long that takes."""
    from sqlalchemy import text

    pid = connection.connection.dbapi_connection.info.backend_pid
    with engine.connect() as other:
        assert other.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid}).scalar()
        deadline = time.monotonic() + 10
        while other.execute(
            text("SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"), {"pid": pid}
        ).scalar_one():
            assert time.monotonic() < deadline, "the server never ended the session"
            other.rollback()
            time.sleep(0.05)


def test_a_tick_whose_session_the_database_ended_is_let_go_and_the_next_one_taken(
    engine, state, ran, logged
):
    """A database restart ends the session that holds a tick's lock, and the lock with it.

    Closing that connection at the tick's end rolls back first, and the rollback fails on a
    session the server already ended. Until October 2026 that error left `cycle` and the
    jobs service exited at its next tick boundary, every time PostgreSQL restarted; Docker's
    restart policy started it again, and the new process, which remembered no tick, ran the
    current one a second time (`recover`'s quarter hour, observed on a Community install).
    Now the worker lets the dead session go, says so, keeps its own record of the tick it
    ran, and takes the next tick as usual.
    """
    job = FAST[0]
    now = time.time()
    scheduler = schedule.Scheduler(engine, state=state, jobs=(job,))
    second = schedule.Scheduler(engine, state=state, jobs=(job,))
    try:
        assert scheduler.cycle(now) == {job.name: 0}
        end_session(engine, scheduler.held[job.name].connection)
        # The same worker does not run the tick it already ran, lock or no lock.
        assert scheduler.cycle(now) == {}
        later = now + job.interval
        assert scheduler.cycle(later) == {job.name: 0}
        # The next tick's lock is a real one: another replica cannot take it.
        assert second.cycle(later) == {}
    finally:
        scheduler.close()
        second.close()
    assert ran == [job.name, job.name]
    lost = [event for event in logged() if event["event"] == "dependency.unavailable"]
    assert lost == [
        {
            "event": "dependency.unavailable",
            "command": job.name,
            "tick": schedule.tick(job, now),
            "code": "SESSION_LOST",
        }
    ]


def test_a_worker_whose_sessions_the_database_ended_stops_quietly(engine, state, ran, logged):
    """`serve` closes every held connection when it stops; a database restart before then
    must not turn a clean stop into a traceback."""
    scheduler = worker(engine, state)
    scheduler.cycle()
    for held in list(scheduler.held.values()):
        end_session(engine, held.connection)
    scheduler.close()
    assert scheduler.held == {}
    codes = [event.get("code") for event in logged() if event["event"] == "dependency.unavailable"]
    assert codes == ["SESSION_LOST"] * len(FAST)


def test_a_tick_that_comes_while_the_database_is_down_is_taken_once_it_is_back(
    engine, state, ran, logged
):
    """A tick boundary inside a restart finds nothing listening. `notify` ticks every fifteen
    seconds, so a restart of a few seconds meets one more often than not. The worker says it
    could not ask, starts nothing, and asks again on its next pass; until October 2026 the
    refused connection left `cycle` and the service exited.

    A port nothing listens on refuses the connection exactly as PostgreSQL's own port does
    while the server is stopped."""
    now = time.time()
    refused = schedule.engine_for(
        local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app").set(port=1)
    )
    scheduler = worker(refused, state)
    try:
        assert scheduler.cycle(now) == {}
        # Asked again a second later, and said once: one line per job and tick, not per pass.
        assert scheduler.cycle(now + 1) == {}
        assert scheduler.held == {} and ran == []
        scheduler.engine = engine
        assert set(scheduler.cycle(now)) == {job.name for job in FAST}
    finally:
        scheduler.close()
        refused.dispose()
    unavailable = [event for event in logged() if event["event"] == "dependency.unavailable"]
    assert [(event["command"], event["code"]) for event in unavailable] == [
        (job.name, "DATABASE_UNAVAILABLE") for job in FAST
    ]
    assert not [event for event in logged() if event["event"] == "job.held_elsewhere"]


def test_a_job_whose_credential_is_not_written_yet_waits(engine, tmp_path, ran):
    """`docker compose up` starts this service before quickstart has issued anything.

    Waiting is right and failing is not: the installation is mid-flight, and a service that
    exited would have to be restarted by hand at the end of a three-command install.
    """
    scheduler = worker(engine, tmp_path)
    try:
        assert scheduler.cycle() == {}
        assert scheduler.held == {}
        (tmp_path / schedule.JOBS_FILE).write_text('{"tenant": "token"}', encoding="utf-8")
        assert set(scheduler.cycle()) == {"recover", "notify"}
    finally:
        scheduler.close()
    assert sorted(ran) == ["notify", "recover"]


def test_a_failing_job_is_its_own_outcome_and_not_the_run_s(engine, state, monkeypatch):
    """One job's refusal must not stop the other two, or the service's next tick."""

    def fake(job, state, *, limit=50, collector=None, checkpoints=None):
        code = 2 if job.name == "notify" else 0
        return [sys.executable, "-c", f"raise SystemExit({code})"]

    monkeypatch.setattr(schedule, "argv", fake)
    scheduler = worker(engine, state)
    try:
        outcomes = scheduler.cycle()
    finally:
        scheduler.close()
    assert outcomes == {"recover": 0, "notify": 2, "monitor-process": 0}


def test_the_documented_command_is_what_runs(state):
    """The vector is the runbook's command, with no shell and nothing interpolated."""
    recover = schedule.argv(FAST[0], state)
    assert recover[:4] == [sys.executable, "-m", "execbound.cli", "recover"]
    assert recover[4:] == ["--all-tenants", "--limit", "50"]
    notify = schedule.argv(FAST[1], state)
    assert notify[3:] == ["notify", "--all-tenants", "--limit", "50"]
    monitor = schedule.argv(FAST[2], state)
    assert monitor[:4] == [sys.executable, "-m", "execbound.monitoring.commands", "process"]
    assert str(state / schedule.MONITOR_FILE) in monitor
    assert all("&" not in part and ";" not in part for part in recover + notify + monitor)


def test_the_shipped_intervals_are_the_documented_ones():
    assert {job.name: job.interval for job in schedule.JOBS} == {
        "recover": 900,
        "notify": 15,
        "monitor-process": 300,
        "audit-verify": 3600,
    }
    assert len({job.key for job in schedule.JOBS}) == len(schedule.JOBS)


def test_the_invitations_drain_runs_only_where_mail_can_be_sent(state):
    """Without a relay the drain refuses to start, so a job service that scheduled it anyway
    would log a failed job every two minutes on every installation that has no mail; with one,
    it retries what the console's first send could not deliver."""
    assert schedule.jobs_for(False) == schedule.JOBS
    assert schedule.jobs_for(True) == (*schedule.JOBS, schedule.INVITATIONS)
    jobs = schedule.jobs_for(True)
    assert len({job.key for job in jobs}) == len(jobs)
    assert schedule.argv(schedule.INVITATIONS, state) == [
        sys.executable,
        "-m",
        "execbound.cli",
        "invitations-run",
        "--limit",
        "50",
    ]


def test_hv15_the_summary_job_needs_a_relay_and_the_flag(state):
    """The weekly summary is scheduled only with a relay and the `mail` block's flag (#678),
    on its own lock key, and runs the command the runbook documents."""
    assert schedule.WEEKLY_SUMMARY not in schedule.jobs_for(False)
    assert schedule.WEEKLY_SUMMARY not in schedule.jobs_for(False, weekly_summary=True)
    assert schedule.WEEKLY_SUMMARY not in schedule.jobs_for(True)
    jobs = schedule.jobs_for(True, weekly_summary=True)
    assert jobs == (*schedule.JOBS, schedule.INVITATIONS, schedule.WEEKLY_SUMMARY)
    assert len({job.key for job in jobs}) == len(jobs)
    assert schedule.WEEKLY_SUMMARY.key == 9_006
    assert schedule.argv(schedule.WEEKLY_SUMMARY, state) == [
        sys.executable,
        "-m",
        "execbound.cli",
        "weekly-summary-run",
        "--limit",
        "50",
    ]


def test_mc7_collection_runs_only_where_a_key_file_collector_key_or_platform_app_is_present(
    tmp_path,
):
    """`collect-due` every five minutes on its own lock key (#678), scheduled only where the
    state directory holds operator key files or the collector's directory holds its key, the
    key a rotation is retiring or the platform app's credential, which open key-file, sealed
    and consented connections; every other job, and each one's key, as before."""
    state = tmp_path / "state"
    state.mkdir()
    assert schedule.collect_configured(state) is False
    (state / schedule.KEY_FILES).mkdir()
    assert schedule.collect_configured(state) is True
    keyed = tmp_path / "keyed"
    keyed.mkdir()
    (keyed / schedule.COLLECTOR_KEY).write_text("{}", encoding="utf-8")
    assert schedule.collect_configured(tmp_path / "empty", keyed) is True
    consented = tmp_path / "consented"
    consented.mkdir()
    (consented / schedule.SCOUT_APP).write_text("{}", encoding="utf-8")
    assert schedule.collect_configured(tmp_path / "empty", consented) is True
    assert (schedule.COLLECT.name, schedule.COLLECT.key, schedule.COLLECT.interval) == (
        "collect-due",
        9_005,
        300,
    )
    assert schedule.jobs_for(False) == schedule.JOBS
    assert schedule.jobs_for(False, collect=True) == (*schedule.JOBS, schedule.COLLECT)
    assert schedule.jobs_for(True, weekly_summary=True) == (
        *schedule.JOBS,
        schedule.INVITATIONS,
        schedule.WEEKLY_SUMMARY,
    )
    assert schedule.jobs_for(True, weekly_summary=True, collect=True) == (
        *schedule.JOBS,
        schedule.INVITATIONS,
        schedule.WEEKLY_SUMMARY,
        schedule.COLLECT,
    )
    assert schedule.jobs_for(False, notify=False, collect=True) == (
        schedule.RECOVER,
        schedule.MONITOR,
        schedule.AUDIT_VERIFY,
        schedule.COLLECT,
    )
    every = (*schedule.JOBS, schedule.INVITATIONS, schedule.WEEKLY_SUMMARY, schedule.COLLECT)
    assert len({job.key for job in every}) == len(every)
    # No credential: the scheduled actor of every active workspace.
    assert schedule.argv(schedule.COLLECT, state) == [
        sys.executable,
        "-m",
        "execbound.monitoring.commands",
        "collect-due",
        "--all-tenants",
        "--key-files",
        str(state / schedule.KEY_FILES),
    ]


def test_mc3_the_collectors_key_is_read_from_its_own_directory_and_named_on_the_command(
    tmp_path,
):
    """The collector's private key sits in a directory only the jobs container mounts, never
    in the state directory the gateway also mounts (#678). Where it is present, collection is
    scheduled and `collect-due` is given it; where it is not, the command names no key."""
    state = tmp_path / "state"
    state.mkdir()
    collector = tmp_path / "collector"
    collector.mkdir()
    assert schedule.collect_configured(state, collector) is False
    (collector / schedule.COLLECTOR_KEY).write_text("{}", encoding="utf-8")
    assert schedule.collect_configured(state, collector) is True
    assert schedule.argv(schedule.COLLECT, state, collector=collector) == [
        sys.executable,
        "-m",
        "execbound.monitoring.commands",
        "collect-due",
        "--all-tenants",
        "--key-files",
        str(state / schedule.KEY_FILES),
        "--collector-key",
        str(collector / schedule.COLLECTOR_KEY),
    ]
    # During a rotation the key being retired sits beside it, and the command names both, so
    # a connection sealed to either is opened.
    (collector / schedule.COLLECTOR_PREVIOUS_KEY).write_text("{}", encoding="utf-8")
    assert schedule.argv(schedule.COLLECT, state, collector=collector)[-4:] == [
        "--collector-key",
        str(collector / schedule.COLLECTOR_KEY),
        "--collector-key",
        str(collector / schedule.COLLECTOR_PREVIOUS_KEY),
    ]
    # The key being retired alone still schedules collection, and is still named.
    (collector / schedule.COLLECTOR_KEY).unlink()
    assert schedule.collect_configured(state, collector) is True
    assert schedule.argv(schedule.COLLECT, state, collector=collector)[-2:] == [
        "--collector-key",
        str(collector / schedule.COLLECTOR_PREVIOUS_KEY),
    ]
    # The state directory no longer counts as holding the collector's key.
    (state / schedule.COLLECTOR_KEY).write_text("{}", encoding="utf-8")
    (state / schedule.COLLECTOR_PREVIOUS_KEY).write_text("{}", encoding="utf-8")
    assert schedule.collect_configured(state, tmp_path / "absent") is False
    assert schedule.argv(schedule.COLLECT, state, collector=tmp_path / "absent")[-1] == str(
        state / schedule.KEY_FILES
    )
    assert schedule.DEFAULT_COLLECTOR == Path("/srv/collector")


def test_mc3_the_platform_apps_credential_is_read_from_the_collectors_directory(tmp_path):
    """The platform app's certificate reads every directory that consented to it, so it sits
    with the collector's key in the directory only the jobs container mounts. Where it is
    present, collection is scheduled and `collect-due` is given it."""
    state = tmp_path / "state"
    state.mkdir()
    collector = tmp_path / "collector"
    collector.mkdir()
    (collector / schedule.SCOUT_APP).write_text("{}", encoding="utf-8")
    assert schedule.SCOUT_APP == "scout-app.json"
    assert schedule.collect_configured(state, collector) is True
    assert schedule.argv(schedule.COLLECT, state, collector=collector)[-2:] == [
        "--platform-app",
        str(collector / schedule.SCOUT_APP),
    ]
    (collector / schedule.COLLECTOR_KEY).write_text("{}", encoding="utf-8")
    assert schedule.argv(schedule.COLLECT, state, collector=collector)[-4:] == [
        "--collector-key",
        str(collector / schedule.COLLECTOR_KEY),
        "--platform-app",
        str(collector / schedule.SCOUT_APP),
    ]
    # Never from the state directory, which the gateway mounts too.
    (state / schedule.SCOUT_APP).write_text("{}", encoding="utf-8")
    assert schedule.collect_configured(state, tmp_path / "absent") is False
    assert "--platform-app" not in schedule.argv(
        schedule.COLLECT, state, collector=tmp_path / "absent"
    )


def test_hv15_whether_the_summary_is_on_is_read_from_the_runtime_configuration(tmp_path):
    installed = install.install(tmp_path / "install", telemetry=False)
    path = installed.directory / "private" / "gateway.json"
    assert schedule.weekly_summary_configured(None) is False
    document = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**document, "mail": RELAY}), encoding="utf-8")
    assert schedule.weekly_summary_configured(path) is False
    path.write_text(
        json.dumps({**document, "mail": {**RELAY, "weekly_summary": True}}), encoding="utf-8"
    )
    assert schedule.weekly_summary_configured(path) is True
    path.write_text(
        json.dumps(
            {**document, "mail": {**RELAY, "weekly_summary": True, "weekly_summary_daily_cap": 0}}
        ),
        encoding="utf-8",
    )
    assert schedule.weekly_summary_configured(path) is False


RELAY = {
    "host": "smtp.example.com",
    "port": 465,
    "tls": "tls",
    "username": "relay",
    "password": "relay-password",
    "from": "execbound@example.com",
}


def test_whether_mail_is_configured_is_read_from_the_runtime_configuration(tmp_path):
    """The file `execbound init` writes has no relay; add one and the drain is scheduled. A
    file that cannot be read or does not validate schedules no drain: every other job reads
    the same file and refuses it on its own."""
    installed = install.install(tmp_path / "install", telemetry=False)
    path = installed.directory / "private" / "gateway.json"
    assert schedule.mail_configured(None) is False
    assert schedule.mail_configured(tmp_path / "absent.json") is False
    assert schedule.mail_configured(path) is False
    document = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**document, "mail": RELAY}), encoding="utf-8")
    assert schedule.mail_configured(path) is True
    path.write_text(json.dumps({**document, "mail": {**RELAY, "tls": "none"}}), encoding="utf-8")
    assert schedule.mail_configured(path) is False
    path.write_text("{not json", encoding="utf-8")
    assert schedule.mail_configured(path) is False


def test_the_jobs_command_schedules_the_drain_from_the_configuration_it_runs_with(
    tmp_path, monkeypatch, capsys
):
    """`execbound jobs` reads the runtime configuration its own jobs load, and hands the
    scheduler whether it names a relay."""
    from execbound import cli

    installed = install.install(tmp_path / "install", telemetry=False)
    path = installed.directory / "private" / "gateway.json"
    seen: list[bool] = []
    summaries: list[bool] = []

    collects: list[bool] = []

    def serve(
        url, *, state, collector, checkpoints, once, limit, mail, notify, weekly_summary, collect
    ):
        assert checkpoints == schedule.DEFAULT_CHECKPOINTS
        seen.append((mail, notify))
        summaries.append(weekly_summary)
        collects.append(collect)
        return {}

    monkeypatch.setattr(schedule, "serve", serve)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://jobs@127.0.0.1:1/execbound")
    monkeypatch.setattr(sys, "argv", ["execbound", "jobs", "--once"])
    monkeypatch.delenv("EXECBOUND_RUNTIME_CONFIG", raising=False)
    cli._main()
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(path))
    cli._main()
    document = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**document, "mail": RELAY}), encoding="utf-8")
    cli._main()
    path.write_text(
        json.dumps({**document, "mail": RELAY, "notifications": [destination("email")]}),
        encoding="utf-8",
    )
    cli._main()
    assert seen == [(False, False), (False, False), (True, False), (True, True)]
    # The weekly summary only where the relay turns it on (#678).
    path.write_text(
        json.dumps({**document, "mail": {**RELAY, "weekly_summary": True}}), encoding="utf-8"
    )
    cli._main()
    assert seen == [(False, False), (False, False), (True, False), (True, True), (True, False)]
    assert summaries == [False, False, False, False, True]
    # Collection only where the state directory holds a key file (#678).
    state = tmp_path / "state"
    (state / schedule.KEY_FILES).mkdir(parents=True)
    monkeypatch.setattr(sys, "argv", ["execbound", "jobs", "--once", "--state", str(state)])
    cli._main()
    assert collects == [False, False, False, False, False, True]
    capsys.readouterr()


TENANT = "00000000-0000-4000-8000-000000000001"


def destination(kind):
    """One destination of each kind, with only the fields its kind carries."""
    item = {"destination_id": f"soc-{kind}", "tenant_id": TENANT, "kind": kind}
    if kind in {"webhook", "security-events"}:
        return item | {"url": "https://alerts.example.net/hook", "secret": "s" * 32}
    if kind == "email":
        return item | {"to": "soc@example.com"}
    return item | {"url": "https://hooks.slack.com/services/T0/B0/secret"}


def test_ay14_notify_runs_only_where_an_approval_destination_is_configured(tmp_path):
    """A fifteen-second drain is a process every fifteen seconds, so the jobs service schedules
    it only where an approval can be announced; an audit-export destination announces none."""
    installed = install.install(tmp_path / "install", telemetry=False)
    path = installed.directory / "private" / "gateway.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert schedule.destinations_configured(None) is False
    assert schedule.destinations_configured(tmp_path / "absent.json") is False
    assert schedule.destinations_configured(path) is False
    path.write_text(
        json.dumps({**document, "notifications": [destination("security-events")]}),
        encoding="utf-8",
    )
    assert schedule.destinations_configured(path) is False
    for kind in ("webhook", "email", "slack", "teams"):
        listed = [destination("security-events"), destination(kind)]
        # An email destination is valid only beside the relay it is sent through.
        relay = {"mail": RELAY} if kind == "email" else {}
        path.write_text(
            json.dumps({**document, **relay, "notifications": listed}), encoding="utf-8"
        )
        assert schedule.destinations_configured(path) is True, kind
    path.write_text("{not json", encoding="utf-8")
    assert schedule.destinations_configured(path) is False
    # A path that cannot be read as a file, whoever the tests run as.
    assert schedule.destinations_configured(tmp_path) is False
    assert schedule.jobs_for(False) == schedule.JOBS
    assert schedule.NOTIFY not in schedule.jobs_for(False, notify=False)
    assert schedule.jobs_for(False, notify=False) == (
        schedule.RECOVER,
        schedule.MONITOR,
        schedule.AUDIT_VERIFY,
    )
    assert schedule.jobs_for(True, notify=True) == (*schedule.JOBS, schedule.INVITATIONS)
    assert schedule.jobs_for(True, notify=False) == (
        schedule.RECOVER,
        schedule.MONITOR,
        schedule.AUDIT_VERIFY,
        schedule.INVITATIONS,
    )


def starts(monkeypatch, commands):
    """Record when each job is started, with `commands` standing in for each one's work."""
    started: list[tuple[str, float]] = []

    def fake(job, state, *, limit=50, collector=None, checkpoints=None):
        started.append((job.name, time.monotonic()))
        return [sys.executable, "-c", commands[job.name]]

    monkeypatch.setattr(schedule, "argv", fake)
    return started


def test_ay14_a_long_job_does_not_hold_notify_back(engine, state, monkeypatch):
    """Recover runs for three seconds while notify ticks every second: notify keeps running
    beside it, and recover, due again at every tick, is never started a second time."""
    jobs = (
        schedule.Job("recover", 77_011, 1, schedule.JOBS_FILE),
        schedule.Job("notify", 77_012, 1, schedule.JOBS_FILE),
    )
    started = starts(monkeypatch, {"recover": "import time; time.sleep(3)", "notify": "pass"})
    scheduler = schedule.Scheduler(engine, state=state, jobs=jobs)
    try:
        until = time.monotonic() + 2.6
        while time.monotonic() < until:
            scheduler.cycle(wait=False)
            time.sleep(0.2)
        assert "recover" in scheduler.running
        outcomes = scheduler.finish()
    finally:
        scheduler.close()
    assert [name for name, _ in started].count("recover") == 1
    assert [name for name, _ in started].count("notify") >= 2
    # The last notify may still be running when the loop ends; finish waits for it too.
    assert outcomes["recover"] == 0 and set(outcomes.values()) == {0}


def test_ay14_once_waits_for_every_job_it_started(state, monkeypatch):
    """`--once` reports every job's outcome, the slow one's too, as it did when jobs ran one
    after another."""
    starts(
        monkeypatch,
        {
            "recover": "import time; time.sleep(1)",
            "notify": "pass",
            "monitor-process": "raise SystemExit(3)",
            "audit-verify": "raise SystemExit(1)",
        },
    )
    url = local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app")
    outcomes = schedule.serve(url, state=state, once=True)
    assert outcomes == {"recover": 0, "notify": 0, "monitor-process": 3, "audit-verify": 1}
    assert schedule.serve(url, state=state, once=True, notify=False) == {
        "recover": 0,
        "monitor-process": 3,
        "audit-verify": 1,
    }


def test_ay14_a_timed_out_job_is_stopped_by_its_own_handle(engine, state, monkeypatch, caplog):
    jobs = (schedule.Job("recover", 77_021, 900, schedule.JOBS_FILE),)
    started = starts(monkeypatch, {"recover": "import time; time.sleep(30)"})
    scheduler = schedule.Scheduler(engine, state=state, jobs=jobs, timeout=1)
    logger = logging.getLogger("execbound")
    handler = logging.NullHandler()
    logger.addHandler(handler)
    try:
        with caplog.at_level(logging.INFO, logger="execbound"):
            begun = time.monotonic()
            assert scheduler.cycle() == {"recover": 124}
            assert time.monotonic() - begun < 10
    finally:
        logger.removeHandler(handler)
        scheduler.close()
    assert scheduler.running == {}
    assert len(started) == 1
    events = [
        record.execbound["event"] for record in caplog.records if hasattr(record, "execbound")
    ]
    assert "job.timed_out" in events
