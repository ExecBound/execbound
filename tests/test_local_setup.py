# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/local_setup.py` when Docker Compose cannot start the database.

A failed `docker compose up` used to end the script with a fixed sentence and discard what
Compose had said, so a CI run that stopped there left no cause in its log. The script now
prints the tail of Compose's own output, and before it does, it hides every value the
checkout's `.env` holds: the passwords and the database URLs that carry them. These cases
fake `run_program`, so they need no Docker, database or network, and they write `.env` under
`tmp_path` rather than the checkout's own.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import assert_secret_free

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("local_setup", ROOT / "scripts" / "local_setup.py")
assert _spec is not None and _spec.loader is not None
local_setup = importlib.util.module_from_spec(_spec)
sys.modules["local_setup"] = local_setup
_spec.loader.exec_module(local_setup)

LOCAL_CONTEXT = json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}])
DAEMON_ERROR = (
    "Error response from daemon: driver failed programming external connectivity on "
    "endpoint execbound-ci-db-1: Bind for 127.0.0.1:55442 failed: port is already allocated"
)


def env_values(root: Path) -> dict[str, str]:
    """Every value the `.env` under `root` holds, read the way a person would read it."""
    values = {}
    for line in (root / ".env").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key] = value
    return values


def fake_compose(outputs: list[str], returncode: int = 1):
    """A `run_program` whose Docker context is local and whose `compose up` fails with
    `outputs`' text, which a caller fills once it knows what `.env` holds."""
    calls: list[list[str]] = []

    def run(arguments: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        if arguments[:3] == ["docker", "context", "inspect"]:
            return subprocess.CompletedProcess(arguments, 0, LOCAL_CONTEXT, "")
        assert arguments[:2] == ["docker", "compose"], arguments
        return subprocess.CompletedProcess(arguments, returncode, "".join(outputs), "")

    run.calls = calls  # type: ignore[attr-defined]
    return run


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    """A scratch checkout root, so `.env` and `local-data/` land under `tmp_path`."""
    monkeypatch.setattr(local_setup, "ROOT", tmp_path)
    return tmp_path


def test_a_failed_compose_start_prints_composes_last_lines_without_any_env_value(
    checkout, monkeypatch, capsys
):
    outputs: list[str] = []
    run = fake_compose(outputs)
    monkeypatch.setattr(local_setup, "run_program", run)
    monkeypatch.setattr(sys, "argv", ["local_setup.py", "--compose-project", "execbound-ci"])

    real_ensure = local_setup.ensure_environment

    def ensure_then_echo() -> dict[str, str]:
        # The script writes `.env` here; Compose's output then repeats every value in it, the
        # way a daemon or interpolation error can quote the environment it was given.
        values = real_ensure()
        written = env_values(checkout)
        assert set(written) == set(values)
        lines = [f" Container execbound-ci-db-1  Creating step {n:02d}\n" for n in range(15)]
        lines += [f" {key}={value} rejected\n" for key, value in written.items()]
        lines += [f"{DAEMON_ERROR}\n"]
        outputs.append("".join(lines))
        return values

    monkeypatch.setattr(local_setup, "ensure_environment", ensure_then_echo)

    assert local_setup.main() == 1

    printed = capsys.readouterr()
    written = env_values(checkout)
    assert len(written) == 6
    assert_secret_free(printed.err, known=tuple(written.values()))
    assert_secret_free(printed.out, known=tuple(written.values()))
    assert "Docker Compose startup failed" in printed.err
    # The daemon's own reason, the last line Compose wrote, is the point of the change.
    assert DAEMON_ERROR in printed.err
    # Each line that quoted a value is still there, with the value hidden.
    for key in written:
        assert f" {key}=[redacted] rejected" in printed.err
    # Twenty lines, the last twenty: 15 steps + 6 quoted values + 1 error = 22.
    assert "step 01" not in printed.err
    assert "step 02" in printed.err
    assert run.calls[-1][-3:] == ["up", "-d", "db"]


@pytest.mark.parametrize("output", ["", "\n  \n\n"])
def test_a_failed_compose_start_that_printed_nothing_says_so(checkout, monkeypatch, output):
    monkeypatch.setattr(local_setup, "run_program", fake_compose([output]))

    with pytest.raises(local_setup.SetupError) as raised:
        local_setup.start_docker({"POSTGRES_PASSWORD": "x" * 40}, "execbound-ci")

    message = str(raised.value)
    assert "Docker Compose startup failed" in message
    assert "printed nothing" in message


def test_a_successful_compose_start_raises_nothing(checkout, monkeypatch):
    run = fake_compose(["Container execbound-ci-db-1  Started\n"], returncode=0)
    monkeypatch.setattr(local_setup, "run_program", run)

    local_setup.start_docker({"POSTGRES_PASSWORD": "x" * 40}, "execbound-ci")

    assert run.calls[-1][:4] == ["docker", "compose", "-p", "execbound-ci"]


@pytest.mark.parametrize(
    ("text", "hidden", "expected"),
    [
        # A URL that holds a password is hidden whole, not around the password.
        (
            "url=https://owner:inner-value@host.example/db pw=inner-value",
            ["inner-value", "https://owner:inner-value@host.example/db"],
            "url=[redacted] pw=[redacted]",
        ),
        # Overlapping values: no character of either survives.
        ("xabcdy", ["abc", "bcd"], "x[redacted]y"),
        ("xabcdy", ["ab", "cd"], "x[redacted]y"),
        # Every occurrence, including occurrences that overlap one another.
        ("aaaa", ["aa"], "[redacted]"),
        ("a1b1c", ["1"], "a[redacted]b[redacted]c"),
        # An empty value hides nothing and cannot stall the search.
        ("abc", ["", "b"], "a[redacted]c"),
        ("abc", [], "abc"),
    ],
)
def test_redaction_hides_every_occurrence_of_every_value(text, hidden, expected):
    assert local_setup.redact(text, hidden) == expected
