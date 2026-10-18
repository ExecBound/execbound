# SPDX-License-Identifier: AGPL-3.0-only
"""The jobs service: the scheduled work of a one-host installation, run once each.

`execbound jobs` is one container running `recover` every fifteen minutes, `notify` every
fifteen seconds, `monitor-process` every five minutes and `audit-verify` every hour, and
`collect-due` every five minutes where this host holds something to collect with. Until it
existed the runbook left the first three to the operator, which means that on a Community
installation they were not run at all: nothing settles a committed operation, nobody is told an
approval is waiting, and no monitoring observation ever becomes a finding. `notify` is
scheduled only where the runtime configuration names an approval destination, `invitations-run`
only where it names a mail relay, `monitor-process` runs with `--deliver` wherever the runtime
configuration reads, and `collect-due` only where the state directory holds a key-files
directory (for operator key-file connections) or the collector's directory holds its key or the
key a rotation is retiring (for sealed ones) or the platform app's credential (for consented
directories); each is decided once, when the service starts (`jobs_for`). Neither the
collector's key nor the platform app's credential is ever in the state directory: the gateway
mounts that, and the gateway must never hold a key that opens a sealed monitoring key or signs
for the app that reads every consented directory, so the collector's directory is the jobs
container's alone.

**Jobs run side by side.** Each due job is started as its own process and the scheduler does
not wait for it, so a recover pass that runs for minutes never holds a notification back
(#678). A job runs at most one process at a time: one still running when its next tick comes is
not started again for that tick, and the tick's lock is left for another replica to take.

**The interval is a tick, and the lock is held for all of it.** A tick is
`floor(now / interval)`, a number every replica computes identically from the clock. A worker
takes `pg_try_advisory_lock(job, tick)` and keeps it until that tick ends rather than releasing
it when the run finishes. A lock released at the end of a run would stop two replicas running a
job at the same moment and would not stop the second one running the same tick a second later,
which is the guarantee #411 asks for. The
cost is one idle connection per job. A replica that dies drops its connections, its ticks
become available, and another replica takes the next one, which is what should happen.

A database restart ends every session, and so every lock, at once. The worker is not taken
down with them: it lets a session the server ended go at its tick's end, reports a tick it
could not ask about while nothing answered, and asks again next pass. It keeps its own record
of a tick it ran, so it never runs that tick twice; another replica may run the rest of it,
as when a replica dies.

The two-argument advisory lock is a different lock space from the one-argument form the
monitoring store uses, so these keys cannot collide with those.

This reaches two jobs services. It does not reach a job an operator runs by hand, which takes
no lock at all, and the runbook says so.
"""

from __future__ import annotations

import subprocess  # nosec B404 - fixed argument vectors, never a shell; see _start
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import IO, TYPE_CHECKING

from execbound.logging_schema import log_event

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from sqlalchemy.engine import URL, Connection, Engine

DEFAULT_STATE = Path("/srv/state")
# The collector's key pair, mounted read-only into the jobs container and nowhere else.
DEFAULT_COLLECTOR = Path("/srv/collector")
# The retained audit heads `audit-verify` places on each chain: in the private directory, which
# every container mounts read-only, so no process the installation runs can replace one.
DEFAULT_CHECKPOINTS = Path("/srv/private/checkpoints")
JOBS_FILE = "jobs.json"
MONITOR_FILE = "monitor.json"
# Long enough for a bounded run of fifty, short enough that a wedged job frees its tick.
JOB_TIMEOUT_SECONDS = 600
POLL_SECONDS = 1.0
INT32 = 0x7FFFFFFF


@dataclass(frozen=True)
class Job:
    """One scheduled command, its interval and its own lock key.

    The key is written down rather than hashed from the name: `hash()` is randomized per
    process, so two replicas would compute two different keys and each would run every tick.
    """

    name: str
    key: int
    interval: int
    needs: str
    # Whether the job's own log lines go straight to this service's log rather than through the
    # tail of its standard error written after a failure: a line that is the job's finding must
    # reach the log whole, however many there are, and even when the job is stopped at its
    # timeout.
    own_log: bool = False
    # Whether `monitor-process` routes and sends findings too (`--deliver`, #31): wherever the
    # jobs service has a runtime configuration that reads (`runtime_configured`).
    deliver: bool = False


RECOVER = Job("recover", 9_001, 900, JOBS_FILE)
# Every fifteen seconds (#678): an approval's default deadline is two minutes, and
# a message the drain sends a minute and a half late leaves nobody time to decide.
NOTIFY = Job("notify", 9_002, 15, JOBS_FILE)
MONITOR = Job("monitor-process", 9_003, 300, MONITOR_FILE)
# Every workspace's audit chain verified again (#154, #159), hourly, with each retained head in
# the checkpoints directory placed on it; a chain that fails is logged as `audit.chain_failed`
# and the run exits 1, which this service records as `job.failed`. Its lines are its findings,
# so they go to this service's log as they are written (`own_log`). Lock 9_007.
AUDIT_VERIFY = Job("audit-verify", 9_007, 3600, JOBS_FILE, own_log=True)
JOBS: tuple[Job, ...] = (RECOVER, NOTIFY, MONITOR, AUDIT_VERIFY)
# `monitor-process` with `--deliver` (#31): the same job, name and lock, wherever a runtime
# configuration reads, so a replica that runs either holds the one tick.
MONITOR_DELIVER = replace(MONITOR, deliver=True)
# The teammate invitations drain: it retries what the console's first send could not deliver.
# It needs a mail relay to send through and refuses to start without one, so it is scheduled
# only where the runtime configuration has a `mail` block (`jobs_for`).
INVITATIONS = Job("invitations-run", 9_004, 120, JOBS_FILE)
# The weekly summary (#678): queued and sent each Monday, hourly so a run a relay refused is
# retried. Only where there is a relay and the `mail` block turns the summary on; lock 9_006.
WEEKLY_SUMMARY = Job("weekly-summary-run", 9_006, 3600, JOBS_FILE)
# Scheduled monitoring collection (#678): every five minutes, each due connection this host
# can open (an operator key file, a sealed key, a consented directory), in every active
# workspace with no credential; lock 9_005. Only where the state directory holds operator key
# files or the collector's directory holds its key, the key a rotation is retiring or the
# platform app's credential (`collect_configured`).
COLLECT = Job("collect-due", 9_005, 300, JOBS_FILE)
KEY_FILES = "key-files"
COLLECTOR_KEY = "collector-private.json"
# The key a rotation is retiring, kept beside the new one until every sealed connection has
# moved, so a connection sealed to either is opened.
COLLECTOR_PREVIOUS_KEY = "collector-previous.json"
COLLECTOR_KEYS = (COLLECTOR_KEY, COLLECTOR_PREVIOUS_KEY)
# The platform app's credential, which reads every directory that consented to the
# deployment's app: in the collector's directory too, for the same reason as its key.
SCOUT_APP = "scout-app.json"
# The kinds that announce an approval; `security-events` exports audit records and announces
# nothing. The same set as `notifications.APPROVAL_KINDS`, which this module does not import.
APPROVAL_DESTINATION_KINDS = frozenset({"webhook", "email", "slack", "teams"})


def jobs_for(
    mail: bool,
    *,
    notify: bool = True,
    weekly_summary: bool = False,
    collect: bool = False,
    deliver: bool = False,
) -> tuple[Job, ...]:
    """The jobs this deployment runs: the approval drain only where something can be
    announced, the invitations drain only where mail can be sent, the weekly summary only
    where mail can be sent and the summary is on, monitoring collection only where this
    host holds something to collect with, and `monitor-process` routes and sends findings
    wherever the runtime configuration reads."""
    jobs = tuple(
        MONITOR_DELIVER if deliver and job is MONITOR else job
        for job in JOBS
        if notify or job is not NOTIFY
    )
    found = (*jobs, INVITATIONS) if mail else jobs
    found = (*found, WEEKLY_SUMMARY) if mail and weekly_summary else found
    return (*found, COLLECT) if collect else found


def collect_configured(state: Path, collector: Path = DEFAULT_COLLECTOR) -> bool:
    """Whether the state directory holds operator key files or the collector's directory holds
    its key, the key a rotation is retiring, or the platform app's credential. Without any
    there is nothing `collect-due` could open, so it is not scheduled at all."""
    return (state / KEY_FILES).is_dir() or any(
        (collector / name).is_file() for name in (*COLLECTOR_KEYS, SCOUT_APP)
    )


def mail_configured(path: Path | None) -> bool:
    """Whether the runtime configuration at `path` names a mail relay. A file that cannot be
    read or does not validate answers no: every other job loads the same file and refuses it
    on its own, so the drain is not the place that says so."""
    if path is None:
        return False
    from execbound.surfaces.configuration import read_configuration

    try:
        return read_configuration(path).mail is not None
    except (OSError, ValueError, RecursionError):
        # `RecursionError` too: JSON nested past the parser's limit, under the size cap, would
        # otherwise crash the service at start, and again at every restart.
        return False


def weekly_summary_configured(path: Path | None) -> bool:
    """Whether the runtime configuration at `path` names a relay with the weekly summary on,
    read as `mail_configured` reads it: anything unreadable answers no."""
    if path is None:
        return False
    from execbound.surfaces.configuration import read_configuration

    try:
        mail = read_configuration(path).mail
    except (OSError, ValueError, RecursionError):
        return False
    return mail is not None and mail.weekly_summary


def destinations_configured(path: Path | None) -> bool:
    """Whether the runtime configuration at `path` names an approval-kind destination whose
    classes include `approvals`: a fifteen second drain is a process every fifteen seconds, so
    it runs only where it can announce something (#31). A file that cannot be read or does not
    validate answers no, as for mail."""
    if path is None:
        return False
    from execbound.surfaces.configuration import read_configuration

    try:
        notifications = read_configuration(path).notifications
    except (OSError, ValueError, RecursionError):
        return False
    return any(
        item.kind in APPROVAL_DESTINATION_KINDS and "approvals" in (item.classes or ("approvals",))
        for item in notifications
    )


def runtime_configured(path: Path | None) -> bool:
    """Whether the runtime configuration at `path` reads (#31). Wherever it does,
    `monitor-process` runs with `--deliver`, findings destination or none: with none, the
    router marks each finding's intent routed with no delivery, so the first destination added
    receives nothing raised before it, and a destination's leftovers still close once it is
    removed. A file that does not read answers no, as for mail, so a broken file stops no
    evaluation. It is read as `process --deliver` reads it (`read_outbound`), not only parsed
    as `mail_configured` parses it: a file that parses but whose origin or destinations
    `--deliver` refuses would fail every scheduled pass."""
    if path is None:
        return False
    from execbound.surfaces.configuration import read_outbound

    try:
        read_outbound(path)
    except ValueError:
        # `read_outbound`'s one refusal, for a file it cannot open, parse or accept; it holds
        # no context, and nothing of the file is logged or printed here.
        return False
    return True


def argv(
    job: Job,
    state: Path,
    *,
    limit: int = 50,
    collector: Path | None = None,
    checkpoints: Path | None = None,
) -> list[str]:
    """The command the runbook documents, as a fixed vector with no shell anywhere."""
    if job.name == AUDIT_VERIFY.name:
        # No credential: every workspace's chain read as the runtime role. The retained heads
        # are passed only where their directory exists; without it each chain is still verified
        # to the head the database keeps.
        command = [sys.executable, "-m", "execbound.cli", job.name, "--all-tenants"]
        if checkpoints is not None and checkpoints.is_dir():
            command += ["--checkpoints", str(checkpoints)]
        return command
    if job.name in {INVITATIONS.name, WEEKLY_SUMMARY.name}:
        # A drain across every tenant through its one definer function: no credential and no
        # tenant to name.
        return [sys.executable, "-m", "execbound.cli", job.name, "--limit", str(limit)]
    if job.name == COLLECT.name:
        # No credential (#503): every active workspace as its scheduled actor, each due
        # connection collected only where this host can open it: a key-file connection where
        # its key file is in the state directory, a sealed one with the collector's key and a
        # consented one with the platform app's credential, both from the collector's directory.
        command = [
            sys.executable,
            "-m",
            "execbound.monitoring.commands",
            "collect-due",
            "--all-tenants",
            "--key-files",
            str(state / KEY_FILES),
        ]
        # The collector's own key opens sealed connections, where this host holds it, and so
        # does the key a rotation is retiring while it is still beside it.
        if collector is not None:
            for name in COLLECTOR_KEYS:
                if (collector / name).is_file():
                    command += ["--collector-key", str(collector / name)]
            # The platform app reads every directory that consented to it, where this host
            # holds its credential.
            if (collector / SCOUT_APP).is_file():
                command += ["--platform-app", str(collector / SCOUT_APP)]
        return command
    if job.name == "monitor-process":
        command = [
            sys.executable,
            "-m",
            "execbound.monitoring.commands",
            "process",
            "--config",
            str(state / MONITOR_FILE),
            "--limit",
            str(limit),
        ]
        if job.deliver:
            # Reads the runtime configuration the jobs container carries (#31).
            command.append("--deliver")
        return command
    return [
        sys.executable,
        "-m",
        "execbound.cli",
        job.name,
        # No credential (#503): `recover` acts in every active workspace as that workspace's
        # scheduler principal, and `notify` in every workspace a destination names with the
        # workspace alone. The jobs file stays the job's `needs`: it is how the scheduler knows
        # quickstart has run, and neither command reads it.
        "--all-tenants",
        "--limit",
        str(limit),
    ]


def tick(job: Job, now: float) -> int:
    """The interval this moment belongs to. Every replica computes the same number."""
    return int(now // job.interval) & INT32


@dataclass
class _Held:
    tick: int
    connection: Connection


@dataclass
class _Running:
    """One job's process. Its output goes to files rather than pipes, so a chatty job can never
    block on a full pipe while nobody is reading it."""

    tick: int
    handle: subprocess.Popen[bytes]
    started: float
    out: IO[bytes]
    err: IO[bytes]


@dataclass
class Scheduler:
    """Holds each job's current tick and the connection whose session owns its lock."""

    engine: Engine
    state: Path = DEFAULT_STATE
    collector: Path = DEFAULT_COLLECTOR
    checkpoints: Path = DEFAULT_CHECKPOINTS
    jobs: Sequence[Job] = JOBS
    limit: int = 50
    timeout: int = JOB_TIMEOUT_SECONDS
    held: dict[str, _Held] = field(default_factory=dict)
    running: dict[str, _Running] = field(default_factory=dict)
    # The last tick each job reported it could not ask about, so an outage is one line per
    # job and tick rather than one a second.
    unavailable: dict[str, int] = field(default_factory=dict)

    def close(self) -> None:
        for name in list(self.held):
            self._release(name)

    def finish(self) -> dict[str, int]:
        """Wait for every process still running, each within its own timeout."""
        return {name: self._wait(name) for name in list(self.running)}

    def _wait(self, name: str) -> int:
        code = self._reap(name, block=True)
        assert code is not None  # a blocking reap always settles the process
        return code

    def _release(self, name: str) -> None:
        held = self.held.pop(name, None)
        if held is None:
            return
        from sqlalchemy.exc import DBAPIError

        # Closing the session releases every advisory lock it holds; unlocking first
        # would be the same thing twice and would fail on a connection already lost.
        try:
            held.connection.close()
        except DBAPIError as error:
            # The server ended the session before its tick did, as a PostgreSQL restart does,
            # and its locks went with it. Closing rolls back first, which fails on a session
            # that is gone; SQLAlchemy recognises the disconnect and discards the connection,
            # and a second close completes. The tick was run, so there is nothing to undo:
            # say so and carry on rather than take the service down with it. Any other
            # error is not this, and still stops the service.
            if not error.connection_invalidated:
                raise
            held.connection.close()
            log_event(
                "dependency.unavailable",
                level="WARNING",
                command=name,
                tick=held.tick,
                code="SESSION_LOST",
            )

    def _take(self, job: Job, at: int) -> bool:
        """Take the tick's lock and keep its session, or say why not: another replica holds
        it, or the database could not be asked. Either way the job is not started, and a
        tick the database could not be asked about is asked about again next pass."""
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError, OperationalError

        try:
            connection = self.engine.connect()
        except OperationalError:
            # Nothing listening, as while PostgreSQL restarts.
            self._unavailable(job, at)
            return False
        try:
            taken = connection.execute(
                text("SELECT pg_try_advisory_lock(:key, :tick)"), {"key": job.key, "tick": at}
            ).scalar_one()
        except DBAPIError as error:
            connection.close()
            # A session the server ended mid-question is the same restart; anything else is
            # not, and still stops the service.
            if not error.connection_invalidated:
                raise
            self._unavailable(job, at)
            return False
        except Exception:
            connection.close()
            raise
        if not taken:
            connection.close()
            log_event("job.held_elsewhere", command=job.name, tick=at)
            return False
        self.held[job.name] = _Held(at, connection)
        return True

    def _unavailable(self, job: Job, at: int) -> None:
        if self.unavailable.get(job.name) == at:
            return
        self.unavailable[job.name] = at
        log_event(
            "dependency.unavailable",
            level="WARNING",
            command=job.name,
            tick=at,
            code="DATABASE_UNAVAILABLE",
        )

    def _start(self, job: Job, at: int) -> None:
        out, err = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        try:
            handle = subprocess.Popen(  # nosec B603 - a fixed vector from `argv`, no shell
                argv(
                    job,
                    self.state,
                    limit=self.limit,
                    collector=self.collector,
                    checkpoints=self.checkpoints,
                ),
                stdout=out,
                # Inherited, not piped, so a job that logs this way can never block on it.
                stderr=None if job.own_log else err,
            )
        except OSError:
            out.close()
            err.close()
            raise
        self.running[job.name] = _Running(at, handle, time.monotonic(), out, err)

    def _reap(self, name: str, *, block: bool) -> int | None:
        """The finished process's exit code, logged; None while it is still running and
        `block` is false. A process past the timeout is stopped through its own handle."""
        run = self.running[name]
        code = run.handle.poll()
        if code is None:
            left = self.timeout - (time.monotonic() - run.started)
            if left > 0 and not block:
                return None
            try:
                code = run.handle.wait(timeout=max(left, 0))
            except subprocess.TimeoutExpired:
                run.handle.kill()
                run.handle.wait()
                code = None
        del self.running[name]
        try:
            if code is None:
                log_event("job.timed_out", level="WARNING", command=name, tick=run.tick)
                return 124
            log_event(
                "job.completed" if code == 0 else "job.failed",
                level="INFO" if code == 0 else "WARNING",
                command=name,
                tick=run.tick,
                exit_code=code,
                duration_ms=int((time.monotonic() - run.started) * 1000),
            )
            if code:
                # The command's own refusal, which names a code and never a value, is what an
                # operator needs; it is this service's report and never its exit status.
                run.err.seek(0)
                sys.stderr.write(run.err.read().decode("utf-8", errors="replace")[-2000:])
                sys.stderr.flush()
            return code
        finally:
            run.out.close()
            run.err.close()

    def due(self, now: float) -> Iterator[tuple[Job, int]]:
        """Each job whose current tick this worker does not already own, and whose previous
        process has finished: one still running keeps its job out of the new tick, and the
        tick's lock is left for another replica rather than taken and not used."""
        for job in self.jobs:
            at = tick(job, now)
            held = self.held.get(job.name)
            if held is not None:
                if held.tick == at:
                    continue
                self._release(job.name)
            if job.name in self.running:
                continue
            yield job, at

    def cycle(self, now: float | None = None, *, wait: bool = True) -> dict[str, int]:
        """One pass: reap what finished, start what is due and takeable, and keep each lock
        until its tick ends. With `wait`, also wait for what this pass started and report it;
        without, report only what finished, so no job waits on another."""
        moment = time.time() if now is None else now
        outcomes: dict[str, int] = {}
        for name in list(self.running):
            if (code := self._reap(name, block=False)) is not None:
                outcomes[name] = code
        started: list[str] = []
        for job, at in self.due(moment):
            if not (self.state / job.needs).exists():
                # Before `execbound quickstart` the installation has no workspace yet, and the
                # file each job needs is quickstart's mark. Say so once a cycle rather than
                # failing: the installation is mid-flight, not broken.
                log_event("job.waiting", command=job.name, reason="CREDENTIAL_UNAVAILABLE")
                continue
            if not self._take(job, at):
                continue
            self._start(job, at)
            started.append(job.name)
        if wait:
            for name in started:
                outcomes[name] = self._wait(name)
        return outcomes


def engine_for(url: str | URL) -> Engine:
    """A pool-free engine: every connection here is held deliberately, for its tick."""
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    from execbound.connection import connect_args, database_url

    parsed = database_url(url)
    return create_engine(
        parsed, poolclass=NullPool, hide_parameters=True, connect_args=connect_args(parsed)
    )


def serve(
    url: str,
    *,
    state: Path = DEFAULT_STATE,
    collector: Path = DEFAULT_COLLECTOR,
    checkpoints: Path = DEFAULT_CHECKPOINTS,
    once: bool = False,
    limit: int = 50,
    poll: float = POLL_SECONDS,
    cycles: int | None = None,
    mail: bool = False,
    notify: bool = True,
    weekly_summary: bool = False,
    collect: bool = False,
    deliver: bool = False,
) -> dict[str, int]:
    """Run the scheduler until the process is stopped, or one pass with `once`, which waits
    for every job it started and returns each one's outcome."""
    engine = engine_for(url)
    scheduler = Scheduler(
        engine,
        state=state,
        collector=collector,
        checkpoints=checkpoints,
        limit=limit,
        jobs=jobs_for(
            mail, notify=notify, weekly_summary=weekly_summary, collect=collect, deliver=deliver
        ),
    )
    # Whether `monitor-process` routes and sends findings, so a runtime configuration that does
    # not read is never a silent switch-off (#31).
    log_event("jobs.started", count=len(scheduler.jobs), deliver=deliver)
    remaining = 1 if once else cycles
    outcomes: dict[str, int] = {}
    try:
        while remaining is None or remaining > 0:
            outcomes = scheduler.cycle(wait=once)
            if remaining is not None:
                remaining -= 1
            if remaining is None or remaining > 0:
                time.sleep(poll)
    except KeyboardInterrupt:  # pragma: no cover - the container's own stop signal
        log_event("jobs.stopped")
    finally:
        # A job is never left running behind the service that started it.
        scheduler.finish()
        scheduler.close()
        engine.dispose()
    return outcomes
