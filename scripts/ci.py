#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run the checks every change to ExecBound must pass, one stage at a time.

The repository's CI workflow calls this script once per stage, and a contributor with
Docker, uv, Node and pnpm can run the same stages on their own machine:

    python3 scripts/ci.py all                # every stage, in order
    python3 scripts/ci.py lint suite         # two of them
    python3 scripts/ci.py --print all        # what would run, without running it

Run it in a fresh clone, never in the checkout you develop in. `database` keeps PostgreSQL's
data in `local-data/docker-postgres`, the directory `compose.yaml` gives local development;
`validation` migrates and seeds that database, and `cleanup` deletes the directory. So a run
that includes `database` refuses to start, before its first command, where that directory
already exists. If an earlier run of this script left it, run `cleanup`, which deletes it; if
it is your development database, use a fresh clone.

Every stage runs from the repository root and leaves what a later one reads in the working
tree: `database` writes `.env` and starts PostgreSQL, `suite` writes the test report
`validation` reads, `image` builds the image `provenance` describes and `fresh-machine`
installs, and `cleanup` removes the containers the others started. A stage that fails, for
any reason, stops the run, and `cleanup` still runs if it was asked for; an interrupted run
does the same before it stops.

Ports, names and the worker count come from the environment, so two runs on one machine can
be kept apart. The defaults are what a fresh GitHub-hosted runner uses:

    POSTGRES_PORT              55442           the test database's loopback port
    EXECBOUND_CI_PROJECT       execbound-ci    the Compose project, and the prefix of every
                                               container name
    EXECBOUND_CI_IMAGE         execbound:ci    the image `image` builds and `fresh-machine` runs
    SMOKE_PORT                 18080           the image smoke test's gateway
    VALIDATION_PORTS           8100,8101,8102  the validation gateway and its two mock providers
    MONITORING_PORTS           8120,8121       the monitoring gateway and its receiver
    FRESH_PORT                 18090           the fresh installation's gateway
    PYTEST_WORKERS             one per CPU,    test processes, each with its own database
                               at most 4
    EXECBOUND_CI_BROWSER_DEPS  unset           1 also installs Chromium's system libraries,
                                               which takes root

Standard library only, so it runs with the system `python3` before anything is installed.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

ROOT = Path(__file__).resolve().parents[1]
BANDIT = "bandit==1.9.4"
POSTGRES_IMAGE = "postgres:17.11"
# What the image smoke test gives the gateway: port 1 on loopback, where nothing listens, so
# liveness answers and readiness refuses. The password is the word "smoke" and opens nothing.
UNREACHABLE_DATABASE = "postgresql+psycopg://smoke:smoke@127.0.0.1:1/execbound"
ROUTE_TREE = "console/src/routeTree.gen.ts"
# compose.yaml's bind mount for PostgreSQL's data, which local development uses too.
DATABASE_DATA = "local-data/docker-postgres"
TENANT_HEAD = "local-data/validation-evidence/tenant-0.head.json"
OTHER_TENANT_HEAD = "local-data/validation-evidence/tenant-1.head.json"
INSTALL = "local-data/fresh-machine"
QUICKSTART_LOG = "local-data/fresh-machine-quickstart.log"
JOBS_LOG = "local-data/fresh-machine-jobs.log"
# What `provenance` writes, and the environment it describes, which `cleanup` removes.
RELEASE = "local-data/release"
RELEASE_ENVIRONMENT = "local-data/release-environment"
IMAGE_ID = "local-data/release-image-id"
CYCLONEDX = "cyclonedx-bom==7.1.0"
# What the provenance document records of the workflow run, from the variables GitHub sets.
GITHUB_FIELDS = ("repository", "ref", "workflow", "run_id")
# Every distribution the image carries, as [name, version] pairs, read inside the image.
DISTRIBUTIONS = (
    "import importlib.metadata as m, json; print(json.dumps("
    '[[(d.metadata["Name"] or ""), d.version or ""] for d in m.distributions()]))'
)
# docs/INSTALL.md's claim: three commands to a first governed decision in under ten minutes.
INSTALL_SECONDS = 600
# The jobs a fresh install schedules. `notify` is not among them: the jobs service schedules it
# only where the runtime configuration names an approval destination (#678), and a fresh
# install names none. `audit-verify` is (#154, #159): it needs nothing configured, and its
# `job.completed` here is a fresh install's chain verifying on the jobs service itself.
SCHEDULED_JOBS = ("recover", "monitor-process", "audit-verify")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?")
REVISION = re.compile(r"[0-9a-f]{0,64}")


class SettingError(Exception):
    """An environment variable this script cannot use. Exit 2."""


class StageFailed(Exception):
    """A command or check that failed. The stage stops there."""


@dataclass(frozen=True)
class Settings:
    postgres_port: int
    project: str
    image: str
    smoke_port: int
    validation_ports: tuple[int, ...]
    monitoring_ports: tuple[int, ...]
    fresh_port: int
    workers: int
    browser_deps: bool
    revision: str

    @property
    def smoke_container(self) -> str:
        return f"{self.project}-smoke"

    @property
    def fresh_project(self) -> str:
        return f"{self.project}-fresh"


def _number(value: str) -> bool:
    """ASCII digits and nothing else. `str.isdigit()` also accepts `²`, which `int()` refuses."""
    return re.fullmatch(r"[0-9]+", value) is not None


def _port(value: str, name: str) -> int:
    if not _number(value) or not 1 <= int(value) <= 65535:
        raise SettingError(f"{name} must be a port from 1 to 65535, not {value!r}")
    return int(value)


def _ports(value: str, name: str, count: int) -> tuple[int, ...]:
    ports = tuple(_port(part, name) for part in value.split(","))
    if len(ports) != count or len(set(ports)) != count:
        raise SettingError(f"{name} must be {count} different ports, comma-separated")
    return ports


def available_cpus() -> int:
    """The CPUs this process may run on: its affinity where the platform reports one, which a
    runner or container can narrow, else every CPU the machine has."""
    affinity = getattr(os, "sched_getaffinity", None)
    if affinity is not None:
        return len(affinity(0))
    return os.cpu_count() or 1


def settings(environ: Mapping[str, str], cpus: int | None = None) -> Settings:
    """This run's ports and names, from the environment or the defaults.

    The worker count's default is one per CPU, `cpus` or else the machine's, at most four: a
    private repository's GitHub-hosted runner has two, where four workers cut one run off and
    put a timed test over its deadline.
    """
    project = environ.get("EXECBOUND_CI_PROJECT", "execbound-ci")
    if not PROJECT.fullmatch(project):
        raise SettingError("EXECBOUND_CI_PROJECT must be lower-case letters, digits, - or _")
    image = environ.get("EXECBOUND_CI_IMAGE", "execbound:ci")
    if not IMAGE.fullmatch(image):
        raise SettingError(f"EXECBOUND_CI_IMAGE is not an image name: {image!r}")
    if cpus is None:
        cpus = available_cpus()
    workers = environ.get("PYTEST_WORKERS", str(min(4, max(1, cpus))))
    if not _number(workers) or not 1 <= int(workers) <= 64:
        raise SettingError("PYTEST_WORKERS must be a whole number from 1 to 64")
    deps = environ.get("EXECBOUND_CI_BROWSER_DEPS", "")
    if deps not in {"", "0", "1"}:
        raise SettingError("EXECBOUND_CI_BROWSER_DEPS must be 1, 0 or unset")
    # GitHub sets the commit being checked; elsewhere the builds record none.
    revision = environ.get("GITHUB_SHA", "")
    if not REVISION.fullmatch(revision):
        raise SettingError("GITHUB_SHA is not a commit")
    validation = environ.get("VALIDATION_PORTS", "8100,8101,8102")
    return Settings(
        postgres_port=_port(environ.get("POSTGRES_PORT", "55442"), "POSTGRES_PORT"),
        project=project,
        image=image,
        smoke_port=_port(environ.get("SMOKE_PORT", "18080"), "SMOKE_PORT"),
        validation_ports=_ports(validation, "VALIDATION_PORTS", 3),
        monitoring_ports=_ports(
            environ.get("MONITORING_PORTS", "8120,8121"), "MONITORING_PORTS", 2
        ),
        fresh_port=_port(environ.get("FRESH_PORT", "18090"), "FRESH_PORT"),
        workers=int(workers),
        browser_deps=deps == "1",
        revision=revision,
    )


def _relative(path: str, cwd: str) -> str:
    return Path(os.path.relpath(ROOT / path, ROOT / cwd)).as_posix()


class Runner:
    """Runs a stage's commands from the repository root, or only prints them.

    A command is written as a shell would read it and split with `shlex`, but no shell ever
    runs it. Each is printed before it runs; the environment a command adds never is, because
    the restore commands carry a password there.
    """

    def __init__(self, config: Settings, environ: Mapping[str, str], *, dry: bool, out: IO[str]):
        self.settings = config
        self.dry = dry
        self.out = out
        # scripts/local_setup.py and compose.yaml read the database's port from here.
        self.environ = {**environ, "POSTGRES_PORT": str(config.postgres_port)}

    def say(self, line: str) -> None:
        print(line, file=self.out, flush=True)

    def run(
        self,
        line: str,
        *extra: str,
        cwd: str = ".",
        stdout: str | None = None,
        stdin: str | None = None,
        env: Mapping[str, str] | None = None,
        quiet: bool = False,
        echo: bool = False,
        check: bool = True,
    ) -> int:
        """Run one command: `line`'s words, then `extra`'s. `stdout` and `stdin` are paths from
        the repository root; `quiet` discards the output, and `echo` prints what went to
        `stdout` once the command has finished."""
        command = [*shlex.split(line), *extra]
        shown = shlex.join(command)
        if stdin:
            shown += " < " + shlex.quote(_relative(stdin, cwd))
        if stdout:
            shown += (" | tee " if echo else " > ") + shlex.quote(_relative(stdout, cwd))
        elif quiet:
            shown += " > /dev/null"
        self.say(shown if cwd == "." else f"(cd {shlex.quote(cwd)} && {shown})")
        if self.dry:
            return 0
        options: dict[str, Any] = {"cwd": ROOT / cwd, "env": {**self.environ, **(env or {})}}
        with contextlib.ExitStack() as files:
            if stdin:
                options["stdin"] = files.enter_context((ROOT / stdin).open("rb"))
            if stdout:
                (ROOT / stdout).parent.mkdir(parents=True, exist_ok=True)
                options["stdout"] = files.enter_context((ROOT / stdout).open("wb"))
            elif quiet:
                options["stdout"] = subprocess.DEVNULL
            try:
                code = subprocess.run(command, check=False, **options).returncode
            except FileNotFoundError:
                raise StageFailed(f"cannot run {command[0]} in {cwd}") from None
        if echo and stdout:
            self.out.write((ROOT / stdout).read_text(encoding="utf-8", errors="replace"))
        if check and code:
            raise StageFailed(f"{shlex.join(command[:4])} ... exited {code}")
        return code

    def expect(self, line: str, wanted: str) -> None:
        """Run a command and require exactly `wanted` on its standard output."""
        self.say(f"{line}  # prints {wanted}")
        if self.dry:
            return
        result = subprocess.run(
            shlex.split(line),
            cwd=ROOT,
            env=self.environ,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode or result.stdout.strip() != wanted:
            raise StageFailed(f"{line} did not print {wanted}")

    def check(self, what: str, test: Callable[[], None]) -> None:
        """A check this script makes itself; `test` raises StageFailed when it fails."""
        self.say(f"# check: {what}")
        if not self.dry:
            test()

    def note(self, what: str) -> None:
        self.say(f"# {what}")

    def value(self, what: str, read: Callable[[], str]) -> str:
        """A value only a run can know, such as an identifier an earlier command wrote."""
        return f"<{what}>" if self.dry else read()

    def glob(self, pattern: str) -> list[str]:
        if self.dry:
            return [pattern]
        found = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.glob(pattern))
        if not found:
            raise StageFailed(f"nothing matches {pattern}")
        return found

    def remove(self, path: str) -> None:
        self.say(f"rm -rf {shlex.quote(path)}")
        if not self.dry:
            shutil.rmtree(ROOT / path, ignore_errors=True)

    def mkdir(self, path: str) -> None:
        self.say(f"mkdir -p {shlex.quote(path)}")
        if not self.dry:
            (ROOT / path).mkdir(parents=True, exist_ok=True)

    def remove_project(self, project: str) -> None:
        """Every container, volume and network a Compose project left, found by its label, so
        that no Compose file is read and none of the variables one needs has to be set."""
        label = f"label=com.docker.compose.project={project}"
        for listing, removal in (
            ("docker ps -aq", "docker rm -f"),
            ("docker volume ls -q", "docker volume rm"),
            ("docker network ls -q", "docker network rm"),
        ):
            self.say(f"{listing} --filter {label} | xargs -r {removal}")
            if self.dry:
                continue
            found = subprocess.run(
                [*listing.split(), "--filter", label], capture_output=True, text=True, check=False
            ).stdout.split()
            if found:
                subprocess.run([*removal.split(), *found], check=False)

    def dotenv(self) -> dict[str, str]:
        """`.env`'s variables, as `set -a; . ./.env` would export them, and PGPASSWORD."""
        if self.dry:
            return {}
        values: dict[str, str] = {}
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if not separator or key.startswith("#"):
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key.strip()] = value
        values["PGPASSWORD"] = values["POSTGRES_PASSWORD"]
        return values


def stage_sync(ci: Runner) -> None:
    ci.run("uv sync --locked")


def stage_lint(ci: Runner) -> None:
    ci.run("uv run ruff check .")
    ci.run("uv run ruff format --check .")
    ci.run("uv run mypy")
    ci.run(f"uvx {BANDIT} -c pyproject.toml -q -r src")


def stage_licences(ci: Runner) -> None:
    """Every Python and npm licence against its DEPENDENCIES.md, and the third-party notices
    against what a release ships. The SBOMs this writes stay in local-data/release/."""
    revision = shlex.quote(ci.settings.revision)
    ci.mkdir("local-data/release")
    ci.run(
        "uv run python scripts/python_sbom.py --lockfile uv.lock --dependencies DEPENDENCIES.md"
        f" --revision {revision} --output local-data/release/sbom-python.cdx.json"
    )
    ci.run("pnpm install --frozen-lockfile", cwd="console")
    ci.run("pnpm licenses list --json", cwd="console", stdout="local-data/console-licenses.json")
    production = "local-data/console-licenses-prod.json"
    ci.run("pnpm licenses list --prod --json", cwd="console", stdout=production)
    ci.run(
        "python3 scripts/console_sbom.py --lockfile console/pnpm-lock.yaml"
        f" --licenses local-data/console-licenses.json --production-licenses {production}"
        f" --dependencies console/DEPENDENCIES.md --revision {revision}"
        " --output local-data/release/sbom-console.cdx.json"
    )
    ci.run(f"uv run python scripts/third_party_notices.py --console-licenses {production} --check")


def stage_console(ci: Runner) -> None:
    """The console's own checks and its build. The build generates the route tree from the
    route files, so a committed tree that differs from what it generates is refused."""
    before = (ROOT / ROUTE_TREE).read_bytes() if (ROOT / ROUTE_TREE).is_file() else b""
    for command in ("install --frozen-lockfile", "typecheck", "lint", "test", "build"):
        ci.run(f"pnpm {command}", cwd="console")

    def unchanged() -> None:
        if (ROOT / ROUTE_TREE).read_bytes() != before:
            raise StageFailed(f"the build rewrote {ROUTE_TREE}; commit what it generates")

    ci.check(f"{ROUTE_TREE} is what the build generates", unchanged)


def stage_tools(ci: Runner) -> None:
    """The maintained MCP client and the agent SDKs the suite drives, each installed apart
    from the locked environment, and the browser the suite's page tests use."""
    ci.run("uv pip install --target .tools/mcp-legacy --require-hashes -r tests/mcp-legacy.txt")
    ci.run(
        "uv pip install --target .tools/sdk-examples --require-hashes"
        " --no-binary claude-agent-sdk -r tests/sdk-examples.txt"
    )
    deps = " --with-deps" if ci.settings.browser_deps else ""
    ci.run(f"uv run playwright install{deps} chromium")


def _no_database_yet() -> None:
    if (ROOT / DATABASE_DATA).exists():
        raise StageFailed(
            f"{DATABASE_DATA} already exists, and this run would migrate, seed and then delete "
            "it. If an earlier run of this script left it, run `cleanup`, which deletes it; if "
            "it is your development database, use a fresh clone"
        )


def stage_database(ci: Runner) -> None:
    config = ci.settings
    ci.check(f"{DATABASE_DATA} does not exist yet", _no_database_yet)
    ci.run(
        f"uv run python scripts/local_setup.py --compose-project {config.project}"
        f" --test-workers {config.workers} --disposable"
    )


def stage_suite(ci: Runner) -> None:
    ci.run("uv run pytest --collect-only -q", stdout="local-data/replay-collected.txt")
    ci.run(
        f"uv run pytest -n {ci.settings.workers} --dist loadfile -q"
        " --junitxml=local-data/replay-full.xml"
    )


def stage_package(ci: Runner) -> None:
    """The server's distributions, the client's, the protocol's and the connectors': each
    carries its licence, and the server's carries the console the `console` stage built."""
    ci.remove("dist")
    ci.run("uv build")
    ci.run("uv build clients/python --out-dir dist/client")
    ci.run("uv build protocol --out-dir dist/protocol")
    ci.run("uv build connectors --out-dir dist/connectors")
    wheels = [
        *ci.glob("dist/*.whl"),
        *ci.glob("dist/client/*.whl"),
        *ci.glob("dist/protocol/*.whl"),
        *ci.glob("dist/connectors/*.whl"),
    ]
    ci.run("uv run python scripts/check_wheel_licences.py", *wheels)
    server = [*ci.glob("dist/execbound-*.whl"), *ci.glob("dist/execbound-*.tar.gz")]
    ci.run("uv run python scripts/check_console_packaged.py", *server)


def stage_validation(ci: Runner) -> None:
    gateway, endpoint, identity = ci.settings.validation_ports
    ci.run("uv run alembic upgrade head")
    ci.run(
        "uv run execbound seed-validation --seed ci-validation"
        f" --output local-data/validation-private --gateway-port {gateway}"
        f" --endpoint-port {endpoint} --identity-port {identity}"
    )
    ci.run(
        "uv run python scripts/validation_demo.py run --private local-data/validation-private"
        " --output local-data/validation-evidence"
    )
    ci.run(
        "uv run python scripts/validation_evidence.py --junit local-data/replay-full.xml"
        " --collected local-data/replay-collected.txt --evidence local-data/validation-evidence"
        " --output local-data/validation-manifest.json"
    )


def stage_restore(ci: Runner) -> None:
    """Back the demonstration database up, restore it beside itself, and prove the restored
    history is the live one, that each tenant is still behind its own fence there, and that
    each replays completely."""
    env = ci.dotenv()
    ci.note("with .env's variables exported, and PGPASSWORD set to its POSTGRES_PASSWORD")
    database = (
        f"docker compose -p {ci.settings.project} --env-file .env -f compose.yaml"
        " exec -T -e PGPASSWORD db"
    )
    ci.run(
        f"{database} pg_dump -U execbound_owner -Fc execbound",
        stdout="local-data/backup.dump",
        env=env,
    )
    ci.run(f"{database} createdb -U execbound_owner execbound_restore", env=env)
    ci.run(
        f"{database} pg_restore -U execbound_owner -d execbound_restore",
        stdin="local-data/backup.dump",
        env=env,
    )
    ci.run(
        "uv run python scripts/verify_restore.py --restored-database execbound_restore"
        f" --compare-live --check-fence --checkpoint {TENANT_HEAD}"
        f" --checkpoint {OTHER_TENANT_HEAD}"
        " --provider-store local-data/validation-private/endpoint.sqlite3"
        " --provider-store local-data/validation-private/identity.sqlite3"
        " --output local-data/restore-report.json",
        env=env,
    )
    for index, head in enumerate((TENANT_HEAD, OTHER_TENANT_HEAD)):
        tenant = ci.value(
            f"tenant_id in {head}",
            lambda head=head: str(
                json.loads((ROOT / head).read_text(encoding="utf-8"))["tenant_id"]
            ),
        )
        ci.run(
            "uv run execbound audit-export --database execbound_restore --tenant",
            tenant,
            "--credential-file",
            f"local-data/validation-private/admin-{index}.token",
            "--output",
            f"local-data/restored-tenant-{index}.json",
            "--checkpoint",
            f"local-data/restored-tenant-{index}.head.json",
            env=env,
        )
        ci.run(
            f"uv run execbound replay --input local-data/restored-tenant-{index}.json"
            f" --trusted-head {head} --output local-data/restored-replay-{index}",
            env=env,
        )

        def complete(index: int = index) -> None:
            path = ROOT / f"local-data/restored-replay-{index}/report.json"
            report = json.loads(path.read_text(encoding="utf-8"))
            if not report["complete"]:
                raise StageFailed(f"restored replay {index} is incomplete: {report['issues']}")
            ci.say(f"restored replay {index} complete: {len(report['decisions'])} decisions")

        ci.check(f"restored tenant {index}'s replay is complete", complete)

    def fenced() -> None:
        # `HOLDS`, not merely no failure: `ALONE` would mean no other tenant of the copy held
        # rows, so the run could not show there was anything for either fence to keep out.
        report = json.loads((ROOT / "local-data/restore-report.json").read_text(encoding="utf-8"))
        fences = sorted(row["fence"] for row in report["tenants"])
        if fences != ["HOLDS", "HOLDS"]:
            raise StageFailed(f"the restored fences are {fences}, not both HOLDS")
        ci.say("restored fences hold for both tenants")

    ci.check("each restored tenant's fence holds", fenced)


def stage_monitoring(ci: Runner) -> None:
    gateway, receiver = ci.settings.monitoring_ports
    ci.run(
        "uv run python -m execbound.monitoring.commands init-demo"
        f" --output local-data/monitoring-private.json --gateway-port {gateway}"
        f" --receiver-port {receiver}"
    )
    ci.run(
        "uv run python scripts/monitoring_demo.py --private local-data/monitoring-private.json"
        " --output local-data/monitoring-evidence"
    )


def _get(url: str) -> tuple[int, str]:
    """One loopback request, never through a proxy the environment names."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=5) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", errors="replace")
    except OSError:
        return 0, ""


def stage_image(ci: Runner) -> None:
    """The runtime image, built from the locked environment and smoke-tested without a
    database: a non-root user, the commands it ships, a migration history it can read, a
    gateway whose liveness answers and whose readiness refuses, no private files, and the core
    console."""
    config = ci.settings
    image = config.image
    ci.run(f"docker build --build-arg EXECBOUND_COMMIT={config.revision} --tag {image} .")
    ci.expect(f"docker run --rm {image} id -u", "10001")
    # An operator's shell session needs a login shell and a private ~/.ssh. The image runs no
    # SSH server of its own.
    ci.run(
        f"docker run --rm {image} sh -c"
        """ 'test "$(getent passwd execbound | cut -d: -f7)" = /bin/sh"""
        """ && test "$(stat -c %a /home/execbound/.ssh)" = 700 && ! command -v sshd'"""
    )
    ci.run(f"docker run --rm {image} execbound --help", quiet=True)
    ci.run(f"docker run --rm {image} execbound-demo --help", quiet=True)
    ci.run(
        f"docker run --rm {image} python -c 'import execbound_client.demo, execbound_client.mcp'"
    )
    ci.run(
        f"docker run --rm {image} python -c"
        """ "import importlib.util; assert all(importlib.util.find_spec(name) is None"""
        """ for name in ('pip', 'ensurepip'))" """
    )
    # Every ExecBound package the image installs carries the licence texts its metadata names, in
    # its dist-info's `licenses/`, so the image ships the terms of what it ships.
    ci.run(
        f"docker run --rm {image} python -c"
        """ "import importlib.metadata as m;"""
        """ want = {'execbound': {'LICENSE', 'THIRD_PARTY_NOTICES.md'},"""
        """ 'execbound-client': {'LICENSE'}, 'execbound-protocol': {'LICENSE'},"""
        """ 'execbound-connectors': {'LICENSE'}};"""
        """ missing = {name: sorted(names - {f.name for f in m.distribution(name).files or ()"""
        """ if f.parent.name == 'licenses'}) for name, names in want.items()};"""
        """ assert not any(missing.values()), missing" """
    )
    ci.run(
        f"docker run --rm -e MIGRATION_DATABASE_URL={UNREACHABLE_DATABASE} {image} alembic history",
        quiet=True,
    )
    container = config.smoke_container
    base = f"http://127.0.0.1:{config.smoke_port}"
    ci.run(f"docker rm -f {container}", quiet=True, check=False)
    try:
        ci.run(
            f"docker run -d --name {container} -p 127.0.0.1:{config.smoke_port}:8000"
            f" -e DATABASE_URL={UNREACHABLE_DATABASE} {image}",
            quiet=True,
        )

        def live() -> None:
            status, body = 0, ""
            for _ in range(30):
                status, body = _get(base + "/health/live")
                if status == 200:
                    break
                time.sleep(1)
            if status != 200 or '"ok"' not in body:
                raise StageFailed(f"{base}/health/live did not answer ok within 30 seconds")

        def refuses() -> None:
            status, _ = _get(base + "/health/ready")
            if status != 503:
                raise StageFailed(f"{base}/health/ready answered {status} without a database")

        ci.check(f"{base}/health/live answers ok within 30 seconds", live)
        ci.check(f"{base}/health/ready refuses with 503", refuses)
    finally:
        ci.run(f"docker rm -f {container}", quiet=True, check=False)
    ci.run(f"docker run --rm {image} sh -c 'test ! -e /srv/execbound/.env && test ! -e /build'")
    ci.run(
        f"docker run --rm {image} python -c"
        """ "from execbound.surfaces.console import packaged_edition;"""
        """ assert packaged_edition() == 'core', packaged_edition()" """
    )


def stage_provenance(ci: Runner) -> None:
    """What the image is made of, checked against the image itself: a CycloneDX SBOM of the
    locked environment the image installs, synced beside it with the Dockerfile's own flags,
    with the Rust crates compiled into cedarpy listed inside its component; the distributions
    the built image actually carries; and `provenance.json`, which binds both to the source
    and its pinned inputs and fails when the SBOM does not describe the image. The release
    workflow publishes these three files with the image."""
    config = ci.settings
    image = config.image
    ci.remove(RELEASE_ENVIRONMENT)
    ci.mkdir(RELEASE)
    ci.note(f"the next command installs into {RELEASE_ENVIRONMENT}, not the project's .venv")
    ci.run(
        "uv sync --locked --no-dev --group showcase --no-editable",
        env={"UV_PROJECT_ENVIRONMENT": str(ROOT / RELEASE_ENVIRONMENT)},
    )
    ci.run(
        f"uvx --from {CYCLONEDX} cyclonedx-py environment {RELEASE_ENVIRONMENT}"
        f" --of JSON --output-reproducible -o {RELEASE}/sbom.cdx.json"
    )
    # The Rust crates compiled into cedarpy, from the SBOM its wheel bundles, listed inside its
    # component. The environment's own interpreter reads them, so they are the shipped wheel's.
    ci.run(
        f"{RELEASE_ENVIRONMENT}/bin/python scripts/release_provenance.py"
        f" --nest-crates {RELEASE}/sbom.cdx.json"
    )
    ci.run(
        f"docker run --rm {image} python -c",
        DISTRIBUTIONS,
        stdout=f"{RELEASE}/image-distributions.json",
    )
    ci.run(f"docker image inspect --format {{{{.Id}}}} {image}", stdout=IMAGE_ID)
    image_id = ci.value("image id", lambda: (ROOT / IMAGE_ID).read_text().strip())
    github = {name: ci.environ.get(f"GITHUB_{name.upper()}", "") for name in GITHUB_FIELDS}
    ci.run(
        "uv run --no-project python scripts/release_provenance.py",
        *("--output", f"{RELEASE}/provenance.json"),
        *("--sbom", f"{RELEASE}/sbom.cdx.json"),
        *("--image-distributions", f"{RELEASE}/image-distributions.json"),
        *("--image-tag", image, "--image-id", image_id),
        *("--repository", github["repository"], "--ref", github["ref"]),
        *("--revision", config.revision),
        *("--workflow", github["workflow"], "--run", github["run_id"]),
    )


def scheduled_jobs(log: str) -> list[str]:
    """What is wrong with two replicas' scheduled-job log, if anything: a job that failed or
    timed out, a job that never completed, no interval found held by the other replica, or
    one interval completed on both replicas. Without a held interval nothing shows the second
    replica ever contended for the lock, so the absence of a double run would prove nothing."""
    runs: Counter[str] = Counter()
    intervals: Counter[tuple[str, str]] = Counter()
    held = 0
    problems: list[str] = []
    for line in log.splitlines():
        start = line.find('{"')
        if start < 0:
            continue
        try:
            row = json.loads(line[start:])
        except ValueError:
            continue
        if row.get("event") == "job.completed":
            runs[row["command"]] += 1
            intervals[row["command"], str(row["tick"])] += 1
        elif row.get("event") == "job.held_elsewhere":
            held += 1
        elif row.get("event") in {"job.failed", "job.timed_out"}:
            problems.append(f"{row.get('command')} did not complete: {row['event']}")
    problems += [f"{name} never ran" for name in SCHEDULED_JOBS if name not in runs]
    if not held:
        problems.append("no interval was found held by the other replica")
    problems += [
        f"{name} ran on both replicas at {tick}"
        for (name, tick), count in sorted(intervals.items())
        if count > 1
    ]
    return problems


def stage_fresh_machine(ci: Runner) -> None:
    """docs/INSTALL.md's three commands, from an empty directory to a first governed decision
    and timed; then a second replica of the jobs service, which must find every interval the
    first one took already held."""
    config = ci.settings
    image = config.image
    ci.run(f"docker build --build-arg EXECBOUND_COMMIT={config.revision} --tag {image} .")
    ci.remove_project(config.fresh_project)
    ci.remove(INSTALL)
    ci.mkdir(INSTALL)
    started = time.monotonic()
    try:
        ci.run(
            f"docker run --rm -u {os.getuid()}:{os.getgid()}",
            "-v",
            f"{ROOT / INSTALL}:/install",
            *shlex.split(
                f"{image} execbound init /install --project {config.fresh_project}"
                f" --image {image} --port {config.fresh_port}"
            ),
        )
        ci.run("docker compose up -d", cwd=INSTALL)
        ci.run(
            "docker compose run --rm gateway execbound quickstart",
            cwd=INSTALL,
            stdout=QUICKSTART_LOG,
            echo=True,
        )
        elapsed = time.monotonic() - started

        def governed() -> None:
            log = (ROOT / QUICKSTART_LOG).read_text(encoding="utf-8", errors="replace")
            for host, outcome in (("ws01", "EXECUTED"), ("ws02", "DENIED")):
                if not re.search(rf"{host}\.example +{outcome}", log):
                    raise StageFailed(f"quickstart did not report {host}.example {outcome}")
            ci.say(f"Three commands to a first governed decision: {elapsed:.0f}s")
            if elapsed > INSTALL_SECONDS:
                raise StageFailed(f"over the ten-minute target: {elapsed:.0f}s")

        ci.check(
            "quickstart executed on ws01.example and denied ws02.example,"
            f" at most {INSTALL_SECONDS} seconds after the first command",
            governed,
        )
        ci.run("docker compose up -d --scale jobs=2", cwd=INSTALL)

        def jobs() -> None:
            log = ""
            for _ in range(60):
                log = subprocess.run(
                    ["docker", "compose", "logs", "jobs"],
                    cwd=ROOT / INSTALL,
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout
                done = log.count('"event":"job.completed"')
                held = log.count('"event":"job.held_elsewhere"')
                if done >= len(SCHEDULED_JOBS) and held >= len(SCHEDULED_JOBS):
                    break
                time.sleep(2)
            (ROOT / JOBS_LOG).write_text(log, encoding="utf-8")
            problems = scheduled_jobs(log)
            if problems:
                raise StageFailed("; ".join(problems))

        ci.check(
            "every scheduled job completes and no interval runs on both replicas"
            f" (docker compose logs jobs, every 2 seconds for up to 2 minutes, into {JOBS_LOG})",
            jobs,
        )
    finally:
        ci.run("docker compose down -v --remove-orphans", cwd=INSTALL, check=False)


def stage_cleanup(ci: Runner) -> None:
    """Whatever the other stages started, whether or not they finished."""
    config = ci.settings
    ci.run(f"docker rm -f {config.smoke_container}", quiet=True, check=False)
    ci.remove(RELEASE_ENVIRONMENT)
    ci.remove_project(config.fresh_project)
    ci.remove_project(config.project)
    # PostgreSQL wrote its data directory through the bind mount as root, so only a container
    # can remove it; mounting a directory that does not exist would create it as root.
    if ci.dry or (ROOT / DATABASE_DATA).is_dir():
        ci.run(
            "docker run --rm -v",
            f"{ROOT / 'local-data'}:/local-data",
            POSTGRES_IMAGE,
            *shlex.split("sh -c 'rm -rf /local-data/docker-postgres'"),
            check=False,
        )


STAGES: dict[str, Callable[[Runner], None]] = {
    "sync": stage_sync,
    "lint": stage_lint,
    "licences": stage_licences,
    "console": stage_console,
    "tools": stage_tools,
    "database": stage_database,
    "suite": stage_suite,
    "package": stage_package,
    "validation": stage_validation,
    "restore": stage_restore,
    "monitoring": stage_monitoring,
    "image": stage_image,
    "provenance": stage_provenance,
    "fresh-machine": stage_fresh_machine,
    "cleanup": stage_cleanup,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--print", dest="dry", action="store_true", help="print each command instead of running it"
    )
    parser.add_argument(
        "stages",
        nargs="+",
        metavar="STAGE",
        choices=[*STAGES, "all"],
        help="all, or any of: " + ", ".join(STAGES),
    )
    arguments = parser.parse_args(argv)
    names = list(STAGES) if "all" in arguments.stages else list(dict.fromkeys(arguments.stages))
    try:
        config = settings(os.environ)
    except SettingError as error:
        print(f"ci: {error}", file=sys.stderr)
        return 2
    if "database" in names and not arguments.dry:
        # Before any stage, not only in `database`: a stage that failed before it would still
        # hand the run to `cleanup`, which deletes the directory this refuses to touch.
        try:
            _no_database_yet()
        except StageFailed as error:
            print(f"ci: database refused: {error}", file=sys.stderr)
            return 1
    ci = Runner(config, os.environ, dry=arguments.dry, out=sys.stdout)
    ci.say(f"export POSTGRES_PORT={config.postgres_port}")
    failed = False
    for index, name in enumerate(names):
        if failed and name != "cleanup":
            continue
        ci.say(f"# {name}")
        try:
            STAGES[name](ci)
        except KeyboardInterrupt:
            # Stopped by hand: what the stages started still comes down, if `cleanup` was asked
            # for and has not run yet, and then the interrupt goes on.
            if "cleanup" in names[index + 1 :]:
                ci.say("# cleanup")
                try:
                    STAGES["cleanup"](ci)
                except Exception as error:
                    print(f"ci: cleanup failed: {error}", file=sys.stderr)
            raise
        except Exception as error:
            # Any failure, including a mistake in a stage itself, still reaches `cleanup`.
            print(f"ci: {name} failed: {error}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
