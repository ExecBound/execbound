# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/ci.py`, the checks the repository's CI workflow runs one stage at a time.

What runs is read through `--print`, which prints each stage's commands in order and runs
none of them, so these tests need no Docker, database, browser or network. The workflow
itself cannot run here; the stages it calls can, and the run that proves them is the CI
itself.
"""

import importlib.util
import io
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("ci_stages", ROOT / "scripts" / "ci.py")
assert _spec is not None and _spec.loader is not None
ci = importlib.util.module_from_spec(_spec)
sys.modules["ci_stages"] = ci
_spec.loader.exec_module(ci)

STAGES = [
    "sync",
    "lint",
    "licences",
    "console",
    "tools",
    "database",
    "suite",
    "package",
    "validation",
    "restore",
    "monitoring",
    "image",
    "provenance",
    "fresh-machine",
    "cleanup",
]
SETTINGS = (
    "POSTGRES_PORT",
    "EXECBOUND_CI_PROJECT",
    "EXECBOUND_CI_IMAGE",
    "SMOKE_PORT",
    "VALIDATION_PORTS",
    "MONITORING_PORTS",
    "FRESH_PORT",
    "PYTEST_WORKERS",
    "EXECBOUND_CI_BROWSER_DEPS",
    "GITHUB_SHA",
)


# What `provenance` copies from GitHub's own variables into the provenance document.
RUN_VARIABLES = (
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_WORKFLOW",
    "GITHUB_RUN_ID",
    "RUNNER_ENVIRONMENT",
)


@pytest.fixture(autouse=True)
def defaults(monkeypatch):
    """Every setting at its default. The CI that runs this suite sets several of them.

    The machine has four CPUs, so the default worker count, which follows the machine, does
    not depend on the one running the suite.
    """
    for name in (*SETTINGS, *RUN_VARIABLES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ci, "available_cpus", lambda: 4)


def printed(capsys, *arguments: str) -> list[str]:
    assert ci.main(["--print", *arguments]) == 0
    return capsys.readouterr().out.splitlines()


def stages(lines: list[str]) -> dict[str, list[str]]:
    """Each stage's printed lines, by the stage's name, in the order they were printed."""
    found: dict[str, list[str]] = {}
    current = None
    for line in lines[1:]:
        heading = re.fullmatch(r"# ([a-z-]+)", line)
        if heading and heading.group(1) in ci.STAGES:
            current = heading.group(1)
            found[current] = []
        else:
            assert current is not None, line
            found[current].append(line)
    return found


def test_the_stages_are_the_workflows_in_order():
    assert list(ci.STAGES) == STAGES


def test_all_prints_every_stage_in_order_and_runs_nothing(capsys, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError(f"--print ran {args}")

    monkeypatch.setattr(subprocess, "run", refuse)
    lines = printed(capsys, "all")
    assert lines[0] == "export POSTGRES_PORT=55442"
    found = stages(lines)
    assert list(found) == STAGES
    assert all(found[name] for name in STAGES), "a stage printed nothing"
    assert found["sync"] == ["uv sync --locked"]
    assert found["lint"] == [
        "uv run ruff check .",
        "uv run ruff format --check .",
        "uv run mypy",
        "uvx bandit==1.9.4 -c pyproject.toml -q -r src",
    ]
    assert found["suite"] == [
        "uv run pytest --collect-only -q > local-data/replay-collected.txt",
        "uv run pytest -n 4 --dist loadfile -q --junitxml=local-data/replay-full.xml",
    ]


def test_the_defaults_are_a_fresh_runners(capsys):
    found = stages(printed(capsys, "all"))
    assert found["database"] == [
        "# check: local-data/docker-postgres does not exist yet",
        "uv run python scripts/local_setup.py --compose-project execbound-ci --test-workers 4"
        " --disposable",
    ]
    validation = " ".join(found["validation"])
    assert "--gateway-port 8100 --endpoint-port 8101 --identity-port 8102" in validation
    assert "--gateway-port 8120 --receiver-port 8121" in " ".join(found["monitoring"])
    image = "\n".join(found["image"])
    assert "--tag execbound:ci ." in image
    assert "--name execbound-ci-smoke -p 127.0.0.1:18080:8000" in image
    fresh = "\n".join(found["fresh-machine"])
    assert "--project execbound-ci-fresh --image execbound:ci --port 18090" in fresh
    assert found["tools"][-1] == "uv run playwright install chromium"
    assert "EXECBOUND_COMMIT= " in image


def test_every_setting_comes_from_the_environment(capsys, monkeypatch):
    monkeypatch.setenv("POSTGRES_PORT", "55642")
    monkeypatch.setenv("EXECBOUND_CI_PROJECT", "execbound-export-runner-2")
    monkeypatch.setenv("EXECBOUND_CI_IMAGE", "execbound:export-runner-2")
    monkeypatch.setenv("SMOKE_PORT", "18280")
    monkeypatch.setenv("VALIDATION_PORTS", "8300,8301,8302")
    monkeypatch.setenv("MONITORING_PORTS", "8320,8321")
    monkeypatch.setenv("FRESH_PORT", "18290")
    monkeypatch.setenv("PYTEST_WORKERS", "2")
    monkeypatch.setenv("EXECBOUND_CI_BROWSER_DEPS", "1")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    lines = printed(capsys, "all")
    assert lines[0] == "export POSTGRES_PORT=55642"
    found = stages(lines)
    assert found["database"] == [
        "# check: local-data/docker-postgres does not exist yet",
        "uv run python scripts/local_setup.py --compose-project execbound-export-runner-2"
        " --test-workers 2 --disposable",
    ]
    assert "uv run pytest -n 2 --dist loadfile" in found["suite"][1]
    assert "--gateway-port 8300 --endpoint-port 8301 --identity-port 8302" in " ".join(
        found["validation"]
    )
    assert "--gateway-port 8320 --receiver-port 8321" in " ".join(found["monitoring"])
    image = "\n".join(found["image"])
    assert f"EXECBOUND_COMMIT={'a' * 40} --tag execbound:export-runner-2 ." in image
    assert "--name execbound-export-runner-2-smoke -p 127.0.0.1:18280:8000" in image
    assert "http://127.0.0.1:18280/health/live" in image
    fresh = "\n".join(found["fresh-machine"])
    assert "--project execbound-export-runner-2-fresh" in fresh
    assert "--image execbound:export-runner-2 --port 18290" in fresh
    assert found["tools"][-1] == "uv run playwright install --with-deps chromium"
    assert f"--revision {'a' * 40}" in " ".join(found["licences"])
    assert "-p execbound-export-runner-2 " in " ".join(found["restore"])
    cleanup = "\n".join(found["cleanup"])
    assert "docker rm -f execbound-export-runner-2-smoke" in cleanup
    assert "com.docker.compose.project=execbound-export-runner-2-fresh" in cleanup
    assert "com.docker.compose.project=execbound-export-runner-2 " in cleanup


@pytest.mark.parametrize(
    "name,value",
    [
        ("POSTGRES_PORT", "not-a-port"),
        ("POSTGRES_PORT", "70000"),
        # A digit to str.isdigit() that int() refuses: a number is ASCII digits and only those.
        ("POSTGRES_PORT", "\u00b2"),
        ("VALIDATION_PORTS", "8100,8101,\u00b2"),
        ("PYTEST_WORKERS", "\u00b2"),
        ("VALIDATION_PORTS", "8100,8101"),
        ("VALIDATION_PORTS", "8100,8100,8102"),
        ("MONITORING_PORTS", "8120"),
        ("PYTEST_WORKERS", "0"),
        ("EXECBOUND_CI_PROJECT", "Two Words"),
        ("EXECBOUND_CI_IMAGE", "execbound:ci; rm -rf /"),
        ("EXECBOUND_CI_BROWSER_DEPS", "yes"),
        ("GITHUB_SHA", "not a commit"),
    ],
)
def test_a_setting_that_cannot_be_used_is_refused_before_anything_runs(
    capsys, monkeypatch, name, value
):
    monkeypatch.setenv(name, value)
    assert ci.main(["--print", "all"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert name in captured.err


@pytest.mark.parametrize("cpus,workers", [(2, 2), (16, 4), (1, 1)])
def test_the_default_worker_count_follows_the_machine(cpus, workers):
    # A private repository's GitHub-hosted runner has two CPUs, where four workers cut one
    # run off and put a timed test over its deadline.
    assert ci.settings({}, cpus=cpus).workers == workers


def test_an_explicit_worker_count_wins_over_the_machine():
    assert ci.settings({"PYTEST_WORKERS": "3"}, cpus=2).workers == 3


def test_only_the_named_stages_are_printed_in_the_order_named(capsys):
    assert list(stages(printed(capsys, "lint", "sync", "lint"))) == ["lint", "sync"]


def test_an_unknown_stage_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as raised:
        ci.main(["--print", "everything"])
    assert raised.value.code == 2


def test_the_restore_commands_never_show_the_password(capsys):
    restore = stages(printed(capsys, "restore"))["restore"]
    assert (
        restore[0]
        == "# with .env's variables exported, and PGPASSWORD set to its POSTGRES_PASSWORD"
    )
    assert all("-e PGPASSWORD db " in line for line in restore[1:4])
    assert not any("PGPASSWORD=" in line for line in restore)


def test_a_failed_stage_skips_the_rest_but_not_cleanup(capsys, monkeypatch):
    """The first `lint` command fails; `suite` never starts, and `cleanup` still runs."""
    ran: list[list[str]] = []

    def fake(command, **options):
        ran.append(list(command))
        code = 1 if command[:3] == ["uv", "run", "ruff"] else 0
        return subprocess.CompletedProcess(command, code, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    assert ci.main(["lint", "suite", "cleanup"]) == 1
    assert ran[0] == ["uv", "run", "ruff", "check", "."]
    assert not any(command[:3] == ["uv", "run", "pytest"] for command in ran)
    assert ["docker", "rm", "-f", "execbound-ci-smoke"] in ran
    assert "ci: lint failed" in capsys.readouterr().err


class Spawned:
    """`subprocess.run`'s stand-in: every command succeeds, and each is kept with the
    environment it was given."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []

    def __call__(self, command, **options):
        self.commands.append(list(command))
        self.environments.append(dict(options.get("env") or {}))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


CLEANUP = ["docker", "rm", "-f", "execbound-ci-smoke"]


def test_a_checkout_that_already_holds_a_database_is_refused_before_anything_runs(
    tmp_path, monkeypatch, capsys
):
    """compose.yaml gives local development `local-data/docker-postgres`. A run there would
    migrate and seed that database in `validation` and delete it in `cleanup`, so `all` stops
    before its first command, `cleanup` included, and the directory is left as it was."""
    data = tmp_path / "local-data" / "docker-postgres"
    data.mkdir(parents=True)
    (data / "PG_VERSION").write_text("17\n", encoding="utf-8")
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    spawned = Spawned()
    monkeypatch.setattr(subprocess, "run", spawned)

    assert ci.main(["all"]) == 1

    assert spawned.commands == []
    assert (data / "PG_VERSION").read_text(encoding="utf-8") == "17\n"
    error = capsys.readouterr().err
    assert "local-data/docker-postgres already exists" in error
    assert (
        "If an earlier run of this script left it, run `cleanup`, which deletes it; if it is "
        "your development database, use a fresh clone" in error
    )


def test_the_database_stage_itself_refuses_a_checkout_that_holds_a_database(tmp_path, monkeypatch):
    (tmp_path / "local-data" / "docker-postgres").mkdir(parents=True)
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    spawned = Spawned()
    monkeypatch.setattr(subprocess, "run", spawned)
    runner = ci.Runner(ci.settings({}), {}, dry=False, out=io.StringIO())

    with pytest.raises(ci.StageFailed, match="run `cleanup`, which deletes it; if it is your"):
        ci.STAGES["database"](runner)

    assert spawned.commands == []


def test_a_fresh_checkout_gets_its_database(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    spawned = Spawned()
    monkeypatch.setattr(subprocess, "run", spawned)

    assert ci.main(["database"]) == 0

    assert spawned.commands == [
        [
            *"uv run python scripts/local_setup.py --compose-project execbound-ci".split(),
            "--test-workers",
            "4",
            "--disposable",
        ]
    ]


def test_a_real_restore_gives_the_database_the_password_and_prints_it_nowhere(
    tmp_path, monkeypatch, capsys
):
    """Run for real, not under `--print`, where `.env` is never read. The run stops at the
    tenant file the validation stage would have written; the commands before it are enough."""
    canary = "canary-password-3f9d61"
    (tmp_path / ".env").write_text(
        f"# local\nPOSTGRES_PASSWORD={canary}\nEXECBOUND_APP_PASSWORD=another\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    spawned = Spawned()
    monkeypatch.setattr(subprocess, "run", spawned)

    assert ci.main(["restore"]) == 1

    printed = capsys.readouterr()
    assert canary not in printed.out
    assert canary not in printed.err
    assert "tenant-0.head.json" in printed.err
    database = [
        environment
        for command, environment in zip(spawned.commands, spawned.environments, strict=True)
        if command[:2] == ["docker", "compose"] and "exec" in command
    ]
    assert len(database) == 3
    assert all(environment["PGPASSWORD"] == canary for environment in database)


def test_an_unexpected_error_in_a_stage_still_reaches_cleanup(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    spawned = Spawned()
    monkeypatch.setattr(subprocess, "run", spawned)

    def broken(runner):
        raise RuntimeError("a mistake in the stage itself")

    monkeypatch.setitem(ci.STAGES, "lint", broken)

    assert ci.main(["lint", "suite", "cleanup"]) == 1

    assert not any(command[:3] == ["uv", "run", "pytest"] for command in spawned.commands)
    assert CLEANUP in spawned.commands
    assert "ci: lint failed: a mistake in the stage itself" in capsys.readouterr().err


def test_an_interrupted_stage_runs_cleanup_before_it_stops(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    spawned = Spawned()
    monkeypatch.setattr(subprocess, "run", spawned)

    def interrupted(runner):
        raise KeyboardInterrupt

    monkeypatch.setitem(ci.STAGES, "suite", interrupted)

    with pytest.raises(KeyboardInterrupt):
        ci.main(["suite", "package", "cleanup"])

    assert CLEANUP in spawned.commands
    assert not any(command[:2] == ["uv", "build"] for command in spawned.commands)
    assert "# package" not in capsys.readouterr().out.splitlines()


def test_an_interrupt_runs_no_cleanup_that_was_not_asked_for(tmp_path, monkeypatch):
    """`cleanup` removes `local-data/docker-postgres`; a run that did not name it never does."""
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    spawned = Spawned()
    monkeypatch.setattr(subprocess, "run", spawned)

    def interrupted(runner):
        raise KeyboardInterrupt

    monkeypatch.setitem(ci.STAGES, "suite", interrupted)

    with pytest.raises(KeyboardInterrupt):
        ci.main(["suite"])

    assert spawned.commands == []


def test_two_replicas_that_share_the_schedule_pass():
    log = "\n".join(
        [
            'jobs-1  | {"event":"job.completed","command":"recover","tick":"1"}',
            'jobs-2  | {"event":"job.held_elsewhere","command":"recover","tick":"1"}',
            'jobs-1  | {"event":"job.completed","command":"notify","tick":"1"}',
            'jobs-2  | {"event":"job.completed","command":"monitor-process","tick":"1"}',
            'jobs-1  | {"event":"job.completed","command":"audit-verify","tick":"1"}',
            "jobs-1  | not json at all",
        ]
    )
    assert ci.scheduled_jobs(log) == []


def test_a_job_twice_in_one_interval_a_job_missing_and_a_failure_are_each_named():
    log = "\n".join(
        [
            '{"event":"job.completed","command":"recover","tick":"7"}',
            '{"event":"job.completed","command":"recover","tick":"7"}',
            '{"event":"job.failed","command":"notify","tick":"7"}',
        ]
    )
    assert ci.scheduled_jobs(log) == [
        "notify did not complete: job.failed",
        "monitor-process never ran",
        "audit-verify never ran",
        "no interval was found held by the other replica",
        "recover ran on both replicas at 7",
    ]


def test_two_replicas_that_never_contend_for_an_interval_fail():
    """Every job completing proves nothing about the lock unless the second replica found at
    least one interval already held."""
    log = "\n".join(
        f'jobs-1  | {{"event":"job.completed","command":"{name}","tick":"1"}}'
        for name in ("recover", "notify", "monitor-process", "audit-verify")
    )
    assert ci.scheduled_jobs(log) == ["no interval was found held by the other replica"]


def test_the_script_runs_with_the_system_python_alone():
    """Standard library only: the workflow calls it before anything is installed."""
    result = subprocess.run(
        ["python3", str(ROOT / "scripts" / "ci.py"), "--print", "sync"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ["PATH"]},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == "uv sync --locked"


def test_provenance_describes_the_image_the_image_stage_built(capsys, monkeypatch):
    monkeypatch.setenv("EXECBOUND_CI_IMAGE", "ghcr.io/execbound/execbound:0.1.0")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    found = stages(printed(capsys, "image", "provenance"))
    assert "--tag ghcr.io/execbound/execbound:0.1.0 ." in "\n".join(found["image"])
    provenance = found["provenance"]
    assert provenance[:5] == [
        "rm -rf local-data/release-environment",
        "mkdir -p local-data/release",
        "# the next command installs into local-data/release-environment, not the project's .venv",
        "uv sync --locked --no-dev --group showcase --no-editable",
        "uvx --from cyclonedx-bom==7.1.0 cyclonedx-py environment local-data/release-environment"
        " --of JSON --output-reproducible -o local-data/release/sbom.cdx.json",
    ]
    # The crates compiled into cedarpy, nested inside its component by the environment's own
    # interpreter, so they are read from the wheel the image installs.
    assert provenance[5] == (
        "local-data/release-environment/bin/python scripts/release_provenance.py"
        " --nest-crates local-data/release/sbom.cdx.json"
    )
    assert provenance[6].startswith("docker run --rm ghcr.io/execbound/execbound:0.1.0 python -c ")
    assert provenance[6].endswith(" > local-data/release/image-distributions.json")
    assert provenance[7] == (
        "docker image inspect --format '{{.Id}}' ghcr.io/execbound/execbound:0.1.0"
        " > local-data/release-image-id"
    )
    assert provenance[8].startswith(
        "uv run --no-project python scripts/release_provenance.py"
        " --output local-data/release/provenance.json --sbom local-data/release/sbom.cdx.json"
        " --image-distributions local-data/release/image-distributions.json"
        " --image-tag ghcr.io/execbound/execbound:0.1.0 --image-id "
    )
    assert f"--revision {'a' * 40} " in provenance[8]
    assert len(provenance) == 9


def test_the_sbom_environment_is_synced_as_the_dockerfile_syncs_the_image(capsys):
    """An SBOM of any other environment would describe something that did not ship. The image
    itself is the final check, and `release_provenance.py` fails on a difference; this keeps
    the two commands from parting in the first place."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    syncs = re.findall(r"^RUN (uv sync [^\n]*)$", dockerfile, re.MULTILINE)
    assert syncs, "the Dockerfile syncs nothing"
    found = stages(printed(capsys, "provenance"))
    assert syncs[-1] in found["provenance"]


class Inspected(Spawned):
    """Every command succeeds, and `docker image inspect` prints an image id."""

    def __call__(self, command, **options):
        if list(command[:3]) == ["docker", "image", "inspect"]:
            options["stdout"].write(b"sha256:" + b"e" * 64 + b"\n")
        return super().__call__(command, **options)


def test_a_real_provenance_run_records_the_run_and_installs_apart(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.setenv("GITHUB_REPOSITORY", "ExecBound/execbound")
    monkeypatch.setenv("GITHUB_REF", "refs/tags/v0.1.0")
    monkeypatch.setenv("GITHUB_WORKFLOW", "Release")
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    spawned = Inspected()
    monkeypatch.setattr(subprocess, "run", spawned)

    assert ci.main(["provenance"]) == 0

    synced = [
        environment
        for command, environment in zip(spawned.commands, spawned.environments, strict=True)
        if command[:2] == ["uv", "sync"]
    ]
    assert len(synced) == 1
    assert synced[0]["UV_PROJECT_ENVIRONMENT"] == str(tmp_path / "local-data/release-environment")
    others = [env for env in spawned.environments if env is not synced[0]]
    assert not any("UV_PROJECT_ENVIRONMENT" in env for env in others)
    (nested,) = [command for command in spawned.commands if "--nest-crates" in command]
    assert nested == [
        "local-data/release-environment/bin/python",
        "scripts/release_provenance.py",
        "--nest-crates",
        "local-data/release/sbom.cdx.json",
    ]
    # After the SBOM is written, and before anything reads it.
    order = [command[:2] for command in spawned.commands]
    assert order.index(["uvx", "--from"]) < spawned.commands.index(nested)
    assert spawned.commands.index(nested) < len(spawned.commands) - 1
    recorded = spawned.commands[-1]
    assert recorded[:5] == ["uv", "run", "--no-project", "python", "scripts/release_provenance.py"]
    values = dict(zip(recorded[5::2], recorded[6::2], strict=True))
    assert values["--image-id"] == "sha256:" + "e" * 64
    assert values["--repository"] == "ExecBound/execbound"
    assert values["--ref"] == "refs/tags/v0.1.0"
    assert values["--workflow"] == "Release"
    assert values["--run"] == "7"
    assert values["--revision"] == "b" * 40


def test_cleanup_removes_the_environment_provenance_described(tmp_path, monkeypatch):
    environment = tmp_path / "local-data" / "release-environment"
    (environment / "bin").mkdir(parents=True)
    kept = tmp_path / "local-data" / "release" / "provenance.json"
    kept.parent.mkdir(parents=True)
    kept.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(ci, "ROOT", tmp_path)
    monkeypatch.setattr(subprocess, "run", Spawned())

    assert ci.main(["cleanup"]) == 0

    assert not environment.exists()
    # What the release publishes outlives the run; only the environment it described goes.
    assert kept.is_file()
