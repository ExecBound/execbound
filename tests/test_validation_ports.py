# SPDX-License-Identifier: AGPL-3.0-only
"""Actual loopback ownership and restart behavior without a database or provider."""

import os
import socket
import sys

import pytest

from execbound_harness.validation_run import DemoServices, HarnessError


def test_active_listener_is_refused_without_stopping_it(tmp_path, monkeypatch):
    def unexpected_spawn(*args, **kwargs):
        pytest.fail("Must not launch on another listener's port")

    monkeypatch.setattr("execbound_harness.validation_run.subprocess.Popen", unexpected_spawn)
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(2)
        port = listener.getsockname()[1]
        running = DemoServices(tmp_path, {"ports": {"endpoint": port}})
        # The refusal names the port: a second run on this machine and a broken
        # harness are otherwise indistinguishable in a log.
        with pytest.raises(HarnessError, match=f"endpoint port {port} is already in use"):
            running.start("endpoint")
        with socket.create_connection(("127.0.0.1", port)):
            accepted, _ = listener.accept()
            accepted.close()
        assert not running.processes


def test_closed_server_with_time_wait_can_reach_new_spawn(tmp_path, monkeypatch):
    class ReachedSpawn(Exception):
        pass

    def reached_spawn(*args, **kwargs):
        raise ReachedSpawn()

    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(2)
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port)) as client:
            accepted, _ = listener.accept()
            # The server actively closes first, retaining TIME_WAIT on POSIX.
            accepted.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b""
            accepted.close()
    monkeypatch.setattr("execbound_harness.validation_run.subprocess.Popen", reached_spawn)
    running = DemoServices(tmp_path, {"ports": {"endpoint": port}})
    with pytest.raises(ReachedSpawn):
        running.start("endpoint")
    assert not running.processes


@pytest.fixture
def held_listeners():
    """Listening sockets for a demo's services, chosen before seeding and held until each
    service starts, which closes it; whatever the test never handed over is closed here."""
    opened: list[socket.socket] = []

    def listeners(*names: str) -> dict[str, socket.socket]:
        made = {name: socket.create_server(("127.0.0.1", 0)) for name in names}
        opened.extend(made.values())
        return made

    yield listeners
    for listener in opened:
        listener.close()


class Spawned(Exception):
    pass


def free_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as probe:
        return probe.getsockname()[1]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot pass a socket by pass_fds")
def test_no_other_process_can_take_the_port_while_the_service_starts(tmp_path, monkeypatch):
    """`start` once checked that the port was free, closed its check and let the service
    bind the port itself a second or two later, after its imports: long enough for another
    process to take it, and the readiness probe, which accepts any answer from a provider's
    port, then answered for that process. At the moment the service is spawned, nobody else
    may be able to bind the port."""
    port = free_port()
    taken = []

    def spawn(*args, **kwargs):
        try:
            with socket.create_server(("127.0.0.1", port)):
                taken.append(True)
        except OSError:
            taken.append(False)
        raise Spawned()

    monkeypatch.setattr("execbound_harness.validation_run.subprocess.Popen", spawn)
    running = DemoServices(tmp_path, {"ports": {"endpoint": port}})
    with pytest.raises(Spawned):
        running.start("endpoint")
    assert taken == [False]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot pass a socket by pass_fds")
def test_the_service_is_handed_the_listener_and_this_process_keeps_no_copy(tmp_path, monkeypatch):
    port = free_port()
    handed = {}

    def spawn(command, *, env, pass_fds, **kwargs):
        (descriptor,) = pass_fds
        assert env["VALIDATION_FD"] == str(descriptor)
        with socket.socket(fileno=os.dup(descriptor)) as listener:
            handed["address"] = listener.getsockname()
            handed["listening"] = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        raise Spawned()

    monkeypatch.setattr("execbound_harness.validation_run.subprocess.Popen", spawn)
    running = DemoServices(tmp_path, {"ports": {"endpoint": port}})
    with pytest.raises(Spawned):
        running.start("endpoint")
    assert handed == {"address": ("127.0.0.1", port), "listening": 1}
    # The spawn failed, so the listener this process bound must be closed, not leaked.
    with socket.create_server(("127.0.0.1", port)):
        pass


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot pass a socket by pass_fds")
def test_a_listener_the_caller_held_since_seeding_is_the_one_handed_over(tmp_path, monkeypatch):
    """A caller that chose its ports before seeding holds them as listeners until the
    services start, so no port is ever free between being chosen and being served."""
    held = socket.create_server(("127.0.0.1", 0))
    port = held.getsockname()[1]
    seen = []

    def spawn(command, *, env, pass_fds, **kwargs):
        seen.append(os.path.samestat(os.fstat(pass_fds[0]), os.fstat(held.fileno())))
        raise Spawned()

    monkeypatch.setattr("execbound_harness.validation_run.subprocess.Popen", spawn)
    running = DemoServices(tmp_path, {"ports": {"endpoint": port}}, listeners={"endpoint": held})
    with pytest.raises(Spawned):
        running.start("endpoint")
    assert seen == [True]
    assert held.fileno() == -1


def test_a_held_listener_on_another_port_is_refused(tmp_path):
    held = socket.create_server(("127.0.0.1", 0))
    port = free_port()
    running = DemoServices(tmp_path, {"ports": {"endpoint": port}}, listeners={"endpoint": held})
    with pytest.raises(HarnessError, match=f"endpoint listener is not on port {port}"):
        running.start("endpoint")
    assert held.fileno() == -1 and not running.processes
