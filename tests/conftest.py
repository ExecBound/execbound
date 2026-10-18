# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests exclusively own their loopback execbound_test database.

Under pytest-xdist each worker owns one of its own, `execbound_test_gw0` and so on, because
`seeded` truncates every table the product owns between tests and two workers sharing one
database would empty each other's rows mid-test. An undistributed run keeps the single
`execbound_test`, so `pytest` with no flags behaves exactly as it always has.
"""

import contextlib
import hashlib
import importlib.util
import os
import secrets
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NamedTuple
from uuid import uuid4

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock; the timing lock is a no-op
    fcntl = None  # type: ignore[assignment]

import pytest
import tenant_fence
from alembic import command
from alembic.config import Config
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from xdist.scheduler import LoadFileScheduling

from execbound.connection import (
    TEST_DATABASE,
    connect_args,
    local_database_url,
    worker_database,
)
from execbound.db import EMPTY_CLAIMS, Database, grant_dormant
from execbound.plugins import LoadedPlugins, PluginError, load_plugins
from execbound.secrets import find_secrets

# Holds every test that reads a document to the `docs` marker, so `pytest -m docs` selects what
# a change to documents alone can break (#748).
pytest_plugins = ["document_reads"]

# `signal_conformance` is shared support code, not a file pytest recognizes as a test module by
# name, so a bare `assert` written there gets pytest's rich rewriting (a readable diff instead
# of a bare `AssertionError`) only if this runs before the module is first imported. This
# conftest is the root one, collected before every test module, so it is early enough.
pytest.register_assert_rewrite("signal_conformance")

# The live Entra probe is not collected unless it is enabled. It cannot simply be skipped:
# `validation_evidence` refuses a junit report containing any `skipped` case, and it also
# requires the collected node set and the junit node set to match, so a collected-and-
# skipped module fails the release gate twice over. Not collecting it keeps it out of both.
# The gate is deliberate — a suite that reports a skip is not a suite that passed — and the
# probe is the one module that must not run without a credential and an explicit opt-in.
collect_ignore = (
    [] if os.environ.get("EXECBOUND_GRAPH_LIVE") == "1" else ["test_graph_live_probe.py"]
)


# Every secret a fixture mints is registered here, so that the suite can prove a rendered
# output does not carry one. The set lives for the session: a value minted in one test is
# still a leak if a later test renders it.
_SECRET_REGISTRY: set[str] = set()

_KINDS = {
    "known": "a fixture-minted credential",
    "pattern": "text shaped like a credential",
    "key": "a forbidden field name",
}


class SecretLeak(AssertionError):
    """A secret reached a rendered output. The message names paths and kinds, never values."""


def remember_secret(value: str) -> str:
    """Register a secret a test read from a response, such as a show-once code."""
    if isinstance(value, str) and value:
        _SECRET_REGISTRY.add(value)
    return value


TEST_URLS = (
    ("TEST_DATABASE_URL", "execbound_app"),
    ("TEST_MIGRATION_DATABASE_URL", "execbound_owner"),
)


def current_test_database() -> str:
    """The database this process owns: the worker's under xdist, the single one otherwise."""
    return worker_database(os.environ.get("PYTEST_XDIST_WORKER"))


TESTS = Path(__file__).resolve().parent


def _directory_plugin(request: pytest.FixtureRequest) -> LoadedPlugins | None:
    """The plugin a test's directory names, loaded, when the test reaches the database
    (`admin_engine` is among its fixtures, directly or through another) and has not opted
    out; None otherwise.

    A directory named for a module that is not a plugin (`tests/plugins/`) is not one. Any
    other refusal is raised: a plugin that fails to load would otherwise run every one of its
    database tests as core, each failing on a permission it was never granted.
    """
    directory = request.path.parent
    if (
        directory == TESTS
        or "admin_engine" not in request.fixturenames
        or request.node.get_closest_marker("no_plugin_grants") is not None
        or importlib.util.find_spec("execbound." + directory.name) is None
    ):
        return None
    try:
        return load_plugins({directory.name: None})
    except PluginError as refused:
        if refused.code == "NOT_A_PLUGIN":
            return None
        raise


@pytest.fixture(autouse=True)
def plugin_directory(request):
    """Every test starts with no plugin's claims honoured; a test under `tests/<plugin>/` runs
    the way that plugin's deployment does (#496).

    The plugin loader records what it loads for the whole process, as a deployment's one load
    does, so the record is reset here first rather than handed from whichever test loaded a
    plugin last to the next. A test module in a directory named for a plugin core can load,
    which reaches the database (`admin_engine` is in its fixture closure), then runs with that
    plugin loaded, so its claims are honoured, and with its claims granted; afterwards every
    dormant grant is taken away, so the next test sees the database an install with no plugin
    sees. The directory names the plugin, core never does, and the self-hosted export has no
    such directory.
    `@pytest.mark.no_plugin_grants` keeps a test in such a directory running as core.

    The reset is this fixture's own patch, not the test's `monkeypatch`: a test that calls
    `monkeypatch.undo()` midway would otherwise put back the record from before the reset,
    dropping the claims the plugin's load honoured while its grants stayed.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("execbound.db._honoured", EMPTY_CLAIMS)
        loaded = _directory_plugin(request)
        if loaded is None:
            yield
            return
        engine = request.getfixturevalue("admin_engine")
        with engine.begin() as conn:
            grant_dormant(conn, loaded.claims)
        try:
            yield
        finally:
            with engine.begin() as conn:
                grant_dormant(conn, EMPTY_CLAIMS)


def pytest_configure(config: pytest.Config) -> None:
    """Point this worker's environment at its own database before anything reads it.

    Forty-six test modules read `TEST_DATABASE_URL` or `TEST_MIGRATION_DATABASE_URL` out of
    the environment directly, and a fixture that quietly used a different database from the
    one those modules connect to would be worse than no isolation at all: the suite would
    seed one database and assert against another. Rewriting the two variables once, here,
    means every one of those modules is correct without being touched. Each worker is its
    own process, so it is changing only its own environment.

    An undistributed run rewrites nothing, so `pytest` with no flags is the run it has
    always been.
    """
    load_dotenv()
    name = current_test_database()
    if name == TEST_DATABASE:
        return
    for variable, username in TEST_URLS:
        raw = os.environ.get(variable)
        if not raw:
            continue
        # Validated first, so the loopback pin, the role pin and the no-query-options rule
        # all still apply to what this process was given. Either name is accepted because
        # this has to be idempotent: a test that runs pytest in a subprocess passes on an
        # environment this hook has already rewritten, and the child inherits
        # `PYTEST_XDIST_WORKER` too, so it runs the hook again on its parent's output. A
        # second pass must be a no-op rather than an INTERNALERROR during startup.
        parsed = local_database_url(raw, databases={TEST_DATABASE, name}, username=username)
        os.environ[variable] = parsed.set(database=name).render_as_string(hide_password=False)


def local_test_url(raw: str, username: str) -> URL:
    """This process's test database, checked as strictly as the single one always was.

    The allowlist stays a set of exactly one name; it is simply this worker's name. Widening
    it to a prefix would have been the easy change and would have given local tooling a
    database name it never checked.
    """
    return local_database_url(raw, databases={current_test_database()}, username=username)


@pytest.fixture(scope="session")
def secret_registry() -> set[str]:
    """The session's minted secrets, for a fixture to add what it mints."""
    return _SECRET_REGISTRY


def assert_secret_free(value, *, known=()) -> None:
    """Refuse a rendered output that carries a secret, naming where and of what kind.

    Accepts text, bytes, a parsed JSON document or an HTTP response. The message is built
    here rather than left to assertion rewriting, because a rewritten assertion would print
    the value that failed it.

    """
    body = getattr(value, "text", None)
    if isinstance(body, str) and hasattr(value, "status_code"):
        value = body
    findings = find_secrets(value, known=(*_SECRET_REGISTRY, *known))
    if findings:
        named = "\n".join(f"  - {_KINDS[f.kind]} at {f.path}" for f in findings)
        raise SecretLeak(f"Secret material reached this output:\n{named}")


@pytest.fixture(scope="session")
def admin_engine():
    """The owner's engine. The owner is a superuser that bypasses row security, so a tenant
    fence set on one of its connections limits nothing: a read through it names its tenant
    in the statement, and `tenant_fence` fails a test whose read did not and needed to."""
    load_dotenv()
    url = os.environ.get("TEST_MIGRATION_DATABASE_URL")
    if not url:
        pytest.fail("Run scripts/local_setup.py: real PostgreSQL test configuration is required")
    parsed = local_test_url(url, "execbound_owner")
    # The owner password is a secret this suite holds; register it so that no rendered
    # output, report or error page may repeat it.
    remember_secret(parsed.password or "")
    engine = create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))
    config = Config("alembic.ini")
    # Each worker migrates its own database. That is N times one `alembic upgrade head` at
    # startup, seconds against a suite of minutes, and it keeps forced RLS, the grants and
    # the `check_runtime` catalog identical in every worker's database because they are
    # built by the same migrations rather than copied from one.
    config.attributes["database_url"] = parsed
    command.upgrade(config, "head")
    yield engine
    engine.dispose()


tenant_fence.install()


@pytest.fixture(autouse=True)
def reports_pacer(monkeypatch):
    """Every Graph read is paced by a clock that moves only when the pacer waits, so a test that
    makes more than five reports requests waits on nothing; the pacer's own tests give it a clock
    of their own (#355). The pacer still counts, waits and refuses exactly as it does live."""
    from execbound.monitoring import graph

    def pacer() -> graph.Pace:
        moment = [0.0]

        def sleep(seconds: float) -> None:
            moment[0] += seconds

        return graph.Pace(monotonic=lambda: moment[0], sleep=sleep)

    monkeypatch.setattr(graph, "PACER", pacer)


@pytest.fixture(autouse=True)
def tenant_fence_guard():
    """Fail a test whose owner read, behind a tenant fence, saw rows the fence excludes."""
    tenant_fence.take()
    yield
    found = tenant_fence.take()
    if found:
        pytest.fail(
            "A read on the owner's connection, fenced to one tenant, returned rows the runtime "
            "role does not see. The owner bypasses row security, so the fence limits nothing: "
            "name the tenant in the statement. At " + ", ".join(found),
            pytrace=False,
        )


@pytest.fixture
def seeded(admin_engine):
    tenants = [uuid4(), uuid4()]
    principals = [uuid4(), uuid4()]
    credentials = [uuid4(), uuid4()]
    # Every tenant has exactly one space from the moment it exists (migration 0041), so
    # every column that carries one has a value and no seeded row invents a second.
    spaces = [uuid4(), uuid4()]
    tokens = [
        remember_secret(f"eb1.{t}.{c}.{secrets.token_urlsafe(32)}")
        for t, c in zip(tenants, credentials, strict=True)
    ]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE execbound.workspace_invitation_messages, "
                "execbound.workspace_invitations, "
                # The weekly summary (#678): messages before subscriptions, both before
                # the principals and tenants they point at.
                "execbound.weekly_summary_messages, execbound.weekly_summary_subscriptions, "
                # Password resets (#678): messages before their rows, both before accounts.
                "execbound.account_messages, execbound.account_recoveries, "
                # Dormancy warnings (#439): before the principals they are addressed to.
                "execbound.dormancy_warnings, "
                # Approval emails (#179): before the approvals and principals they point at.
                "execbound.approval_emails, execbound.approval_email_subscriptions, "
                "execbound.job_tenants, "
                "execbound.workspace_memberships, execbound.user_passwords, "
                "execbound.user_identities, execbound.user_factors, execbound.user_passkeys, "
                "execbound.community_allocations, "
                "execbound.account_login_proofs, execbound.account_sessions, "
                "execbound.account_provider_links, "
                "execbound.user_security_events, "
                "execbound.user_accounts, "
                "execbound.approval_rule_targets, execbound.approval_rule_actions, "
                "execbound.approval_rules, execbound.audit_events, execbound.audit_heads, "
                "execbound.authentication_failures, execbound.approval_notifications, "
                "execbound.export_cursors, execbound.approval_decisions, "
                "execbound.passkey_challenges, execbound.account_passkeys, "
                "execbound.account_preferences, execbound.account_requests, "
                "execbound.product_counts, "
                "execbound.session_assurance, execbound.account_factors, "
                "execbound.account_security_policy, execbound.human_sessions, "
                "execbound.access_role_grants, execbound.access_group_members, "
                "execbound.access_groups, execbound.access_principals, "
                "execbound.monitor_deliveries, execbound.monitor_findings, "
                "execbound.monitor_profiles, "
                "execbound.monitor_observations, execbound.monitor_sources, "
                "execbound.assistant_turns, execbound.agent_bindings, "
                "execbound.principal_passwords, execbound.password_resets, "
                "execbound.principal_identities, "
                # A customer's own identity provider (#177, #241). Before `credentials`,
                # which a directory sign-in row points at, and before `principals`.
                "execbound.federated_sign_ins, execbound.identity_invitations, "
                "execbound.identity_links, execbound.identity_providers, "
                "execbound.monitor_actor_drivers, execbound.monitor_reach_exceptions, "
                "execbound.monitor_agent_reach, "
                "execbound.monitor_agent_grants, execbound.monitor_agents, "
                # Entra consent (0088): attempts before the connections they update, and the
                # tenant-free directory claims, which no foreign key reaches and a TRUNCATE of
                # `monitor_connections` fires no trigger to empty.
                "execbound.monitor_connect_attempts, execbound.monitor_directory_claims, "
                "execbound.monitor_inventory, execbound.monitor_connections, "
                "execbound.resource_claims, execbound.execution_impact, execbound.approvals, "
                "execbound.arcade_hooks, "
                "execbound.execution_events, execbound.execution_keys, execbound.executions, "
                "execbound.approval_scopes, execbound.resource_identities, "
                "execbound.canonical_targets, "
                "execbound.tenant_policy_control, execbound.policy_bundle_lifecycle, "
                "execbound.policy_bundle_contents, "
                # Security signals (0068): records before their sources, and both before
                # the accounts, groups, spaces and principals they point at.
                "execbound.security_signals, execbound.signal_sources, "
                "execbound.agent_runs, execbound.resource_facts, execbound.incidents, "
                "execbound.resource_aliases, "
                "execbound.resources, execbound.operation_mappings, execbound.context_sources, "
                "execbound.connector_accounts, "
                "execbound.principal_group_members, execbound.principal_groups, "
                "execbound.executor_keys, "
                "execbound.signup_messages, execbound.signup_requests, "
                "execbound.onboarding_invitations, execbound.onboarding_slots, "
                "execbound.space_policy_selection, execbound.space_members, "
                "execbound.personal_access_tokens, "
                "execbound.credentials, execbound.principals, execbound.spaces, "
                "execbound.tenants"
            )
        )
        for index, (tenant, principal, credential, token, space) in enumerate(
            zip(tenants, principals, credentials, tokens, spaces, strict=True)
        ):
            # Tenant names are unique case-insensitively since 0028_onboarding.
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
                {"t": tenant, "n": f"Synthetic {index}"},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.spaces"
                    "(tenant_id, space_id, name, created_at, created_by) "
                    "VALUES (:t, :s, 'Default', now(), :p)"
                ),
                {"t": tenant, "s": space, "p": principal},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.principals"
                    "(tenant_id, principal_id, kind, space_id) "
                    "VALUES (:t, :p, 'AGENT', :s)"
                ),
                {"t": tenant, "p": principal, "s": space},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.credentials"
                    "(tenant_id, credential_id, principal_id, token_hash, expires_at) "
                    "VALUES (:t, :c, :p, :h, :e)"
                ),
                {
                    "t": tenant,
                    "c": credential,
                    "p": principal,
                    "h": hashlib.sha256(token.encode()).hexdigest(),
                    "e": datetime.now(UTC) + timedelta(hours=1),
                },
            )
    return {
        "tenants": tenants,
        "principals": principals,
        "credentials": credentials,
        "tokens": tokens,
        "spaces": spaces,
    }


@pytest.fixture
def db(admin_engine, seeded):
    parsed = local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app")
    owner = local_test_url(os.environ["TEST_MIGRATION_DATABASE_URL"], "execbound_owner")
    assert (parsed.host, parsed.port, parsed.database) == (owner.host, owner.port, owner.database)
    database = Database(parsed, pool_size=1)
    yield database
    database.close()


# One measured section at a time on this machine.
#
# When several suites share one machine, each on several workers with a Chromium of its own,
# a test that measures wall-clock time measures its neighbours as much as it measures the
# product: CP12's ten thousand entry import and the approval link's phone budget have both
# run past their bounds under that load on trees that pass alone. The tests that measure
# seconds take this lock around the measurement and nothing else does, so no two of them are
# ever timed against each other. The file is a fixed path every suite and
# worker on the machine agrees on; where nobody else opens it the lock is always free,
# which is exactly right. Windows has no `flock`, and there the section runs unserialised
# as it always has.
TIMING_LOCK = Path("/tmp/execbound-timing.lock")  # noqa: S108 - a lock every suite must share
# The worst wait is every other suite's soak in front of this one, which is minutes, not
# hours; past that something is stuck and a clear failure beats a hung job.
TIMING_LOCK_WAIT_SECONDS = 1200
# The lock stops two measured sections overlapping, which is not the same as a quiet
# machine: with other suites running beside it the phone budget comes in well over its
# bound, because Chromium's four times CPU slowdown compounds with whatever else the host is
# doing. So a measured section also waits for the one minute load average to fall below
# three quarters of the core count. Most of that waiting happens before the lock is taken
# rather than while holding it: a multi-minute wait inside a machine-wide mutex multiplies
# by every suite and every measured section and becomes tens of minutes of queue, which
# would fail the very tests this is here to steady. Once the lock is held the load is given
# a short settle and then read, and that reading travels with the section so a failure says
# what the machine was doing when it was measured.
QUIET_LOAD_FRACTION = 0.75
QUIET_WAIT_SECONDS = 180
QUIET_SETTLE_SECONDS = 20
QUIET_POLL_SECONDS = 3


class Machine(NamedTuple):
    """What the box was doing when a measured section ran."""

    load: float
    cpus: int
    quiet: bool
    note: str


def _load() -> float | None:
    """The one minute load average, or None where the platform has none."""
    try:
        return os.getloadavg()[0]
    except (OSError, AttributeError):  # pragma: no cover - Windows has no load average
        return None


def _quiet_threshold() -> float:
    return QUIET_LOAD_FRACTION * (os.cpu_count() or 1)


def _wait_for_quiet(seconds: float) -> None:
    """Poll until the load falls below the threshold, or until the bound runs out."""
    threshold = _quiet_threshold()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        load = _load()
        if load is None or load < threshold:
            return
        time.sleep(QUIET_POLL_SECONDS)


def _machine(what: str, waited: float) -> Machine:
    """The load as the section starts, in a sentence a failure can carry."""
    cpus = os.cpu_count() or 1
    load = _load()
    if load is None:
        return Machine(0.0, cpus, True, f"{what} ran where the load average is not readable")
    threshold = _quiet_threshold()
    if load < threshold:
        return Machine(
            load, cpus, True, f"{what} ran with the machine quiet, load {load:.1f} on {cpus} cores"
        )
    return Machine(
        load,
        cpus,
        False,
        f"{what} ran with the machine busy: load {load:.1f} on {cpus} cores, still above "
        f"{threshold:.1f} after waiting {waited:.0f} s for it to fall",
    )


@pytest.fixture(scope="session")
def timed_alone():
    """Yields a context manager holding the machine-wide timing lock for its block.

    The block runs alone among the measured sections on this machine and, as far as a
    bounded wait can arrange it, on a quiet one. It yields a `Machine` whose `note` says
    what the load was when the section started; put that in the failure message of whatever
    the section measures, so a failure under load says so instead of looking like a
    regression. Wrap only the measured section. Use it where a test asserts on seconds it
    measured, never to make an ordinary test quieter. A test that asks for it is marked
    `@pytest.mark.timed` (`tests/test_timed_marker.py`).
    """

    @contextlib.contextmanager
    def alone(what: str) -> Iterator[Machine]:
        if fcntl is None:
            yield _machine(what, 0.0)
            return
        # Before the lock, so every suite's waiting overlaps instead of queueing.
        started = time.monotonic()
        _wait_for_quiet(QUIET_WAIT_SECONDS)
        handle = os.open(TIMING_LOCK, os.O_RDWR | os.O_CREAT, 0o666)
        try:
            with contextlib.suppress(PermissionError):
                # A file another suite created keeps its creator's umask otherwise.
                os.fchmod(handle, 0o666)
            deadline = time.monotonic() + TIMING_LOCK_WAIT_SECONDS
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        pytest.fail(
                            f"{what} waited {TIMING_LOCK_WAIT_SECONDS} s for the machine's "
                            f"timing lock ({TIMING_LOCK}) and never got it. Another runner "
                            "is holding it; check for a stuck pytest on this machine."
                        )
                    time.sleep(0.5)
            try:
                # Whoever was in front has just let go, so give the box a moment to settle
                # before reading what this section is about to be measured against.
                _wait_for_quiet(QUIET_SETTLE_SECONDS)
                yield _machine(what, time.monotonic() - started)
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)

    return alone


# The files whose tests take the timing lock, handed to a worker before any other file.
#
# `--dist loadfile` hands each worker whole files, and xdist orders the files by how many tests
# they hold, largest first, which assumes a file lasts as long as its count says. A file that takes
# the lock does not: each measured section first waits up to QUIET_WAIT_SECONDS for a quiet machine
# and then queues for the lock behind every other measured section on the machine, so a file of one
# or two tests can take minutes. Handed out among the last, as files that small are, they would be
# the last tests still running, with the other workers idle. Handed out first, the waiting overlaps
# the rest of the suite. Nothing about the sections themselves changes: the same lock, the same
# quiet wait, the same bounds. Longest first.
# tests/test_suite_order.py fails if a file that takes the lock is missing here, and drives
# the real xdist scheduler, so an xdist upgrade that changes the method below fails there too.
# Home's soak is listed although no suite collects it unless it is named: a file that was not
# collected is not in the queue, so its entry moves nothing.
TIMED_FIRST = (
    "tests/soak_console_home.py",
    "tests/test_arcade_deadline.py",
    "tests/test_browser_approval_speed.py",
    "tests/test_browser_console_soak.py",
    "tests/test_context_provisioning.py",
    "tests/test_egress_deadline.py",
)


class TimedFirstScheduling(LoadFileScheduling):
    """xdist's `loadfile` scheduling, with the files in TIMED_FIRST at the front of its queue."""

    def _assign_work_unit(self, node):
        # The queue is complete by the first assignment; a file a crashed worker gives back
        # rejoins it, and goes to the front again if it is one of these.
        for scope in reversed(TIMED_FIRST):
            if scope in self.workqueue:
                self.workqueue.move_to_end(scope, last=False)
        super()._assign_work_unit(node)


@pytest.hookimpl(optionalhook=True)
def pytest_xdist_make_scheduler(config, log):
    """The scheduler for `--dist loadfile`; any other distribution keeps xdist's own."""
    if config.getvalue("dist") != "loadfile":
        return None
    return TimedFirstScheduling(config, log)
