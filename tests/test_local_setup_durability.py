# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/local_setup.py --disposable`: a CI database that never syncs, and only on request.

`DROP DATABASE` forces a checkpoint, and a checkpoint that has to sync thousands of files on a
disk shared with other runners took minutes: the suite's restricted-owner tests, which build and
drop a database each, waited up to 762 s apiece in their teardown. A CI job's own Compose
database holds nothing worth keeping, so `--disposable` turns off `fsync`, `full_page_writes` and
`synchronous_commit` there. Without it a Compose database is made durable again; a native
cluster, the developer's own, is never touched, and `--disposable` is refused for one.
"""

import importlib.util
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("local_setup", ROOT / "scripts" / "local_setup.py")
assert _spec is not None and _spec.loader is not None
local_setup = importlib.util.module_from_spec(_spec)
sys.modules["local_setup"] = local_setup
_spec.loader.exec_module(local_setup)


class Cluster:
    """A connection as `set_durability` uses one: statements recorded, `SHOW` answered from a
    script of states, one per reading of all three settings."""

    def __init__(self, states: list[str]) -> None:
        self.states = states
        self.statements: list[str] = []
        self.reads = 0

    def execute(self, query):
        text = query if isinstance(query, str) else query.as_string()
        self.statements.append(text)
        cluster = self

        class Result:
            def fetchone(self):
                if not text.startswith("SHOW "):
                    return None
                state = cluster.states[min(cluster.reads // 3, len(cluster.states) - 1)]
                cluster.reads += 1
                return (state,)

        return Result()


@pytest.mark.parametrize(("durable", "verb"), [(False, "SET"), (True, "RESET")])
def test_each_setting_is_set_off_or_reset_then_reloaded(durable, verb):
    cluster = Cluster(["on" if durable else "off"])
    local_setup.set_durability(cluster, durable=durable)
    changes = [statement for statement in cluster.statements if statement.startswith("ALTER")]
    expected = [
        f'ALTER SYSTEM {verb} "{name}"' + ("" if durable else " = off")
        for name in local_setup.DURABILITY
    ]
    assert changes == expected
    assert cluster.statements[len(expected)] == "SELECT pg_reload_conf()"


def test_it_waits_for_the_reload_to_take(monkeypatch):
    monkeypatch.setattr(local_setup.time, "sleep", lambda seconds: None)
    cluster = Cluster(["on", "on", "off"])
    local_setup.set_durability(cluster, durable=False)
    assert cluster.reads == 9


def test_a_setting_that_never_takes_stops_the_setup(monkeypatch):
    clock = iter(range(0, 1000, 5))
    monkeypatch.setattr(local_setup.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(local_setup.time, "sleep", lambda seconds: None)
    with pytest.raises(local_setup.SetupError, match="durability"):
        local_setup.set_durability(Cluster(["on"]), durable=False)


def test_disposable_is_refused_for_a_native_cluster(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["local_setup", "--postgres-bin", "/opt/pg", "--disposable"])
    with pytest.raises(SystemExit) as stopped:
        local_setup.main()
    assert stopped.value.code == 2
    assert "--disposable needs Docker Compose" in capsys.readouterr().err


@pytest.mark.parametrize("asked", [False, True])
def test_the_flag_reaches_provisioning_and_nothing_else_decides_it(monkeypatch, asked):
    seen = {}
    monkeypatch.setattr(local_setup, "ensure_environment", lambda: {})
    monkeypatch.setattr(local_setup, "start_docker", lambda values, project=None: None)
    monkeypatch.setattr(local_setup, "provision", lambda values, **options: seen.update(options))
    argv = [
        "local_setup",
        "--compose-project",
        "execbound-ci",
        *(["--disposable"] if asked else []),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert local_setup.main() == 0
    assert seen == {"native": False, "test_workers": 0, "disposable": asked}


@pytest.mark.integration
def test_the_settings_take_on_real_postgresql_without_changing_the_cluster():
    """Against the suite's own cluster, set to the state it is already in, so no other test's
    database changes under it: the statements are accepted, the reload happens, and the wait
    reads all three settings back."""
    engine = create_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    try:
        raw = engine.raw_connection()
        try:
            connection = raw.driver_connection
            connection.autocommit = True
            durable = connection.execute("SHOW fsync").fetchone() == ("on",)
            local_setup.set_durability(connection, durable=durable)
            found = {
                name: connection.execute(f"SHOW {name}").fetchone()[0]
                for name in local_setup.DURABILITY
            }
        finally:
            raw.close()
    finally:
        engine.dispose()
    assert found == {name: "on" if durable else "off" for name in local_setup.DURABILITY}
