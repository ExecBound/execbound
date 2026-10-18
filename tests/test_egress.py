# SPDX-License-Identifier: AGPL-3.0-only
"""The egress guard on every outbound HTTP destination (#31, decision 7; FD12).

No database and no real host. A stand-in resolver (`egress.RESOLVE`) answers for a name, a
stand-in backend stands in for the network behind the guard, and a loopback HTTP server, with
TLS from a CA the test mints where it needs it, stands in for a receiver. A name that resolves
to an address that is not public, or to an IPv6 address outside global unicast that carries no
IPv4 address, is refused before any connection is opened, however many answers come before it;
the first three addresses are tried in the resolver's order; a loopback literal is reached
directly, and any other literal is checked like a name; a certificate is verified against the
URL's own name; and a lookup that outlasts the deadline is given up, and a send that stalls or
trickles, in the clear or behind TLS, is cut off at its deadline. Those deadlines are proved
here without reading a clock, from what the guard hands the network; the seconds they take are
`tests/test_egress_deadline.py`'s, under the machine's timing lock. Every refusal test stands a
recording backend in for the network, so a guard that let an address through would connect to
nothing real. The chat sender and the signed webhook sender name the refusal
`DESTINATION_NOT_PUBLIC`. The signed sender counts 200, 201, 202 and 204 as delivered (decision
8), gives every other status its code, follows no redirect and reads no response body; the
security event export's set stays 200 and 204 (ruling 6).
"""

import logging
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import httpcore
import httpx
import pytest
from smtp_double import mint
from test_notification_transports import message as approval

from execbound import egress
from execbound.monitoring.delivery import (
    EXPORT_ACCEPTED,
    LocalReceiver,
    post_signed,
    send_notification,
)
from execbound.monitoring.models import MonitorError
from execbound.transports import DELIVERED, SendResult, post_chat, send_chat

PUBLIC = "93.184.216.34"
OTHERS = ("93.184.216.35", "93.184.216.36", "93.184.216.37")


class Resolver:
    """Answers every name with the same addresses, and records each name it was asked."""

    def __init__(self, *addresses: str, fails: bool = False) -> None:
        self.addresses, self.fails, self.asked = addresses, fails, []

    def __call__(self, host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        self.asked.append(host)
        if self.fails:
            raise socket.gaierror("no such name")
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
            for a in self.addresses
        ]


class Changing(Resolver):
    """Answers each lookup with the next of its addresses, as a name pointed elsewhere between
    two sends answers."""

    def __init__(self, *answers: str) -> None:
        super().__init__()
        self.answers = list(answers)

    def __call__(self, host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        self.addresses = (self.answers.pop(0),)
        return super().__call__(host, port, *args, **kwargs)


class Malformed(Resolver):
    """A resolver that fails as `getaddrinfo` does on a name the IDNA codec cannot encode, with
    a `UnicodeError`, or on a name with a null byte in it, with a `ValueError`: neither is an
    `OSError`."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def __call__(self, host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        self.asked.append(host)
        raise self.error


class Broken(Resolver):
    """A resolver with a bug in it: a `TypeError`, which no lookup raises."""

    def __call__(self, host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        self.asked.append(host)
        raise TypeError("a bug, not a failed lookup")


class Slow(Resolver):
    """A resolver whose answer takes `seconds` to come, as a slow nameserver's does, unless the
    test lets it go sooner. `answered` is set once it has answered."""

    def __init__(self, seconds: float, *addresses: str) -> None:
        super().__init__(*addresses)
        self.seconds, self.answered, self.release = seconds, threading.Event(), threading.Event()

    def __call__(self, host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        answer = super().__call__(host, port, *args, **kwargs)
        self.release.wait(self.seconds)
        self.answered.set()
        return answer


class Recorded(httpcore.NetworkStream):
    """A stream that records the timeout of each TLS handshake, read and write it is handed,
    the stream a handshake upgrades to included."""

    def __init__(self, stream: httpcore.NetworkStream, timeouts: list[float | None]) -> None:
        self._stream, self._timeouts = stream, timeouts

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self._timeouts.append(timeout)
        return self._stream.read(max_bytes, timeout)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._timeouts.append(timeout)
        self._stream.write(buffer, timeout)

    def close(self) -> None:
        self._stream.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self._timeouts.append(timeout)
        upgraded = self._stream.start_tls(ssl_context, server_hostname, timeout)
        return Recorded(upgraded, self._timeouts)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class Loopback(httpcore.NetworkBackend):
    """The network behind the guard: records each address the guard connects to, refuses those
    in `refuse`, and connects every other one to one loopback port, or to nothing at all. Every
    timeout the guard hands it, to connect and on each stream it returns, is in `timeouts`."""

    def __init__(self, port: int | None = None, refuse: tuple[str, ...] = ()) -> None:
        self.port, self.refuse, self.attempts = port, set(refuse), []
        self.timeouts: list[float | None] = []
        self._inner = httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.attempts.append(host)
        self.timeouts.append(timeout)
        if self.port is None or host in self.refuse:
            raise httpcore.ConnectError("refused")
        stream = self._inner.connect_tcp(
            "127.0.0.1",
            self.port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        return Recorded(stream, self.timeouts)

    def sleep(self, seconds):
        self._inner.sleep(seconds)


def within(timeouts: list[float | None], deadline: float) -> bool:
    """Whether the guard handed the network at least one timeout and none longer than the
    send's deadline: httpx's own five seconds never reached a socket."""
    return bool(timeouts) and all(t is not None and 0 < t <= deadline for t in timeouts)


@contextmanager
def receiving(
    status: int = 201, tls: ssl.SSLContext | None = None, keep_alive: bool = False
) -> Iterator[tuple[list[str], int]]:
    """A loopback HTTP server answering every POST with `status`, recording each path. With
    `keep_alive` it speaks HTTP/1.1 and keeps a connection open for the client's next request."""
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1" if keep_alive else "HTTP/1.0"

        def do_POST(self) -> None:  # noqa: N802 - the standard library's hook name
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield seen, server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@contextmanager
def trickling() -> Iterator[int]:
    """A loopback server that takes a request and then sends its headers a byte every quarter
    second, for longer than any deadline the tests set."""
    listener = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(65536)
            for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 200:
                try:
                    connection.send(bytes([byte]))
                except OSError:
                    return
                time.sleep(0.25)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()
        thread.join(timeout=60)


@contextmanager
def stalling(tls: ssl.SSLContext | None = None) -> Iterator[tuple[int, list[bytes]]]:
    """A loopback server that takes one connection, completes its TLS handshake where it has
    `tls`, reads the request and never answers, until the test is done with it. It records
    what it read, so a test can tell the request arrived."""
    listener = socket.create_server(("127.0.0.1", 0))
    done = threading.Event()
    received: list[bytes] = []

    def serve() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        stream = connection
        try:
            if tls is not None:
                stream = tls.wrap_socket(connection, server_side=True)
            received.append(stream.recv(65536))
            done.wait(30)
        except OSError:
            return
        finally:
            stream.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], received
    finally:
        done.set()
        listener.close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.7",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:10.0.0.1",
        # IPv6 addresses that carry 10.0.0.7: NAT64, IPv4-compatible, 6to4 and Teredo. The
        # first two `ipaddress` calls global, so only the unwrapping refuses them.
        "64:ff9b::a00:7",
        "::a00:7",
        "2002:a00:7::1",
        "2001:0:4136:e378:8000:63bf:f5ff:fff8",
        # IPv4-translated (`::ffff:0:0:0/96`, SIIT) carrying 10.0.0.7, and a deprecated
        # site-local address: `ipaddress` calls both global, and no public receiver has either.
        "::ffff:0:a00:7",
        "fec0::1",
        # Multicast, which `ipaddress` calls global, in IPv6 as in IPv4.
        "ff0e::1",
        # Unallocated IPv6 outside global unicast (`2000::/3`), carrying no IPv4 address, which
        # `ipaddress` calls global.
        "4000::1",
        "5f00::1",
        "fe00::1",
        "100:0:0:1::1",
        "0:0:1::1",
        "::1:0:0:0",
    ],
)
def test_fd12_a_name_that_resolves_to_an_address_that_is_not_public_is_refused(
    monkeypatch, address
):
    """The network behind the guard is a recording stand-in that leads only to the loopback
    receiver, so a guard that let the address through would reach it, never the address."""
    resolver = Resolver(address)
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    with receiving() as (seen, port):
        network = Loopback(port)
        with egress.guarded_client(backend=network) as client:
            with pytest.raises(httpx.ConnectError) as refused:
                client.post(f"http://receiver.example:{port}/alerts", content=b"{}")
    assert egress.refused(refused.value)
    assert resolver.asked == ["receiver.example"] and network.attempts == [] and seen == []


@pytest.mark.parametrize(
    "address",
    [
        PUBLIC,
        "2606:4700::1111",
        # A public IPv4 address carried by NAT64, IPv4-mapped, IPv4-translated and
        # IPv4-compatible forms, all outside `2000::/3`: what they carry is what is checked.
        "64:ff9b::5db8:d822",
        "::ffff:93.184.216.34",
        "::ffff:0:5db8:d822",
        "::5db8:d822",
    ],
)
def test_fd12_a_public_address_is_public_in_each_form_it_takes(address):
    assert egress.public(address)


def test_fd12_an_answer_past_the_first_three_is_checked_too(monkeypatch):
    """Only three addresses are tried, but every address the resolver answers is checked."""
    monkeypatch.setattr(egress, "RESOLVE", Resolver(PUBLIC, *OTHERS[:2], "10.0.0.7"))
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        with pytest.raises(httpx.ConnectError) as refused:
            client.post("https://receiver.example/alerts", content=b"{}")
    assert egress.refused(refused.value) and network.attempts == []


@pytest.mark.parametrize(
    "url",
    [
        "https://10.0.0.7/",
        "https://169.254.169.254/",
        "https://[::ffff:10.0.0.7]/",
        "https://[fd00::1]/",
    ],
)
def test_fd12_an_address_literal_other_than_loopback_is_checked_like_a_name(url):
    """Only a loopback literal is reached unresolved. Any other literal goes through the real
    `getaddrinfo`, which answers a numeric host without asking DNS, and is refused."""
    assert egress.RESOLVE is socket.getaddrinfo
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        with pytest.raises(httpx.ConnectError) as refused:
            client.post(url, content=b"{}")
    assert egress.refused(refused.value) and network.attempts == []


def test_fd12_one_answer_that_is_not_public_refuses_the_name(monkeypatch):
    monkeypatch.setattr(egress, "RESOLVE", Resolver(PUBLIC, "10.0.0.7"))
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        with pytest.raises(httpx.ConnectError) as refused:
            client.post("https://receiver.example/alerts", content=b"{}")
    assert egress.refused(refused.value) and network.attempts == []


def test_fd12_the_connection_is_made_to_the_address_that_was_checked(monkeypatch):
    resolver = Resolver(PUBLIC)
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        with pytest.raises(httpx.ConnectError) as failed:
            client.post("https://receiver.example/alerts", content=b"{}")
    assert not egress.refused(failed.value)
    assert resolver.asked == ["receiver.example"] and network.attempts == [PUBLIC]


def test_fd12_a_first_address_that_refuses_gives_way_to_the_second(monkeypatch):
    monkeypatch.setattr(egress, "RESOLVE", Resolver(PUBLIC, *OTHERS))
    with receiving(201) as (seen, port):
        network = Loopback(port, refuse=(PUBLIC,))
        with egress.guarded_client(backend=network) as client:
            answer = client.post(f"http://receiver.example:{port}/alerts", content=b"{}")
    assert answer.status_code == 201 and seen == ["/alerts"]
    assert network.attempts == [PUBLIC, OTHERS[0]]


def test_fd12_at_most_three_addresses_are_tried_in_the_resolvers_order(monkeypatch):
    monkeypatch.setattr(egress, "RESOLVE", Resolver(OTHERS[2], PUBLIC, *OTHERS[:2]))
    network = Loopback(1, refuse=(PUBLIC, *OTHERS))
    with egress.guarded_client(backend=network) as client:
        with pytest.raises(httpx.ConnectError) as failed:
            client.post("http://receiver.example:1/alerts", content=b"{}")
    assert not egress.refused(failed.value)
    assert network.attempts == [OTHERS[2], PUBLIC, OTHERS[0]]


def test_fd12_every_send_resolves_and_connects_again(monkeypatch):
    """Keep-alive is off, so a receiver that would hold the connection open still gets a new
    one for each send, resolved and checked again inside its own deadline: a name pointed at a
    private address between two sends is refused at the second, before any connection."""
    resolver = Changing(PUBLIC, "10.0.0.7")
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    with receiving(201, keep_alive=True) as (seen, port):
        network = Loopback(port)
        with egress.guarded_client(backend=network) as client:
            answer = client.post(f"http://receiver.example:{port}/alerts", content=b"{}")
            assert answer.status_code == 201
            with pytest.raises(httpx.ConnectError) as failed:
                client.post(f"http://receiver.example:{port}/alerts", content=b"{}")
    assert egress.refused(failed.value)
    assert seen == ["/alerts"]
    assert resolver.asked == ["receiver.example"] * 2 and network.attempts == [PUBLIC]


def test_fd12_a_loopback_literal_is_reached_without_resolving(monkeypatch):
    resolver = Resolver(fails=True)
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    with receiving(201) as (seen, port), egress.guarded_client() as client:
        assert client.post(f"http://127.0.0.1:{port}/alerts", content=b"{}").status_code == 201
    assert seen == ["/alerts"] and resolver.asked == []


def test_fd12_a_name_that_does_not_resolve_is_unavailable_not_refused(monkeypatch):
    monkeypatch.setattr(egress, "RESOLVE", Resolver(fails=True))
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        with pytest.raises(httpx.ConnectError) as failed:
            client.post("https://receiver.example/alerts", content=b"{}")
    assert not egress.refused(failed.value) and network.attempts == []


@pytest.mark.parametrize(
    "error", [UnicodeError("label empty or too long"), ValueError("embedded null byte")]
)
def test_fd12_a_lookup_that_fails_in_any_other_way_is_unavailable_too(monkeypatch, error):
    """A lookup can fail with something other than an `OSError`: a malformed IDNA name with a
    `UnicodeError`, a name with a null byte with a `ValueError`. The guard treats either as the
    receiver being unavailable, as a failed lookup and not as a bug (nothing reaches the lookup
    thread's `excepthook`), so neither sender lets it escape, and nothing is connected."""
    reported: list[type[BaseException]] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: reported.append(args.exc_type))
    resolver = Malformed(error)
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    named = SimpleNamespace(url="https://receiver.example/alerts", secret="k" * 32)
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        signed = post_signed(named, uuid4(), b"{}", client)
        chat = send_chat(
            "slack", "https://chat.example/services/T0/B0/x", uuid4(), approval(), client
        )
    assert signed == chat == SendResult(False, "RECEIVER_UNAVAILABLE")
    assert resolver.asked == ["receiver.example", "chat.example"] and network.attempts == []
    assert reported == []


def test_fd12_a_bug_in_the_lookup_is_reported_not_taken_for_an_unavailable_receiver(
    monkeypatch,
):
    """Only what a lookup raises, an `OSError`, a `UnicodeError` or a `ValueError`, is the
    receiver being unavailable. Anything else is a programming error: it reaches the lookup
    thread's `excepthook`, which reports it, rather than being folded into a failed send. The
    send still fails, and nothing is connected."""
    reported: list[type[BaseException]] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: reported.append(args.exc_type))
    resolver = Broken()
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    network = Loopback()
    named = SimpleNamespace(url="https://receiver.example/alerts", secret="k" * 32)
    with egress.guarded_client(backend=network, deadline=60) as client:
        began = time.monotonic()
        result = post_signed(named, uuid4(), b"{}", client)
        took = time.monotonic() - began
    assert result == SendResult(False, "RECEIVER_UNAVAILABLE")
    # The lookup's thread ended, so the send does not wait out its deadline. A sixty-second
    # deadline against five seconds keeps a loaded runner from flaking it without the timing
    # lock: a guard that waited would take the whole minute.
    assert took < 5
    assert reported == [TypeError]
    assert resolver.asked == ["receiver.example"] and network.attempts == []


def test_fd12_a_lookup_that_outlasts_the_deadline_is_given_up_as_unavailable(monkeypatch):
    """`getaddrinfo` takes no timeout, and a slow nameserver can hold it for half a minute,
    past a drain's lease. The guard waits for the answer no longer than the send's deadline:
    the send ends unavailable, not refused, before the lookup has answered, with nothing
    connected. The seconds it takes are `tests/test_egress_deadline.py`'s."""
    slow = Slow(10, PUBLIC)
    monkeypatch.setattr(egress, "RESOLVE", slow)
    network = Loopback()
    try:
        with egress.guarded_client(backend=network, deadline=1.5) as client:
            with pytest.raises(httpx.ConnectTimeout) as failed:
                client.post("https://receiver.example/alerts", content=b"{}")
            answered = slow.answered.is_set()
    finally:
        slow.release.set()
    assert not answered and not egress.refused(failed.value)
    assert slow.asked == ["receiver.example"] and network.attempts == []


def test_fd12_tls_is_verified_against_the_urls_own_name(monkeypatch, tmp_path):
    """The certificate the test CA mints names `localhost`. Behind the guard, a URL with that
    name connects, and the same server behind another name fails verification. Each handshake
    names the URL's host, never the address the socket was connected to."""
    ca, cert, key = mint(tmp_path)
    served = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    served.load_cert_chain(cert, key)
    named: list[str | None] = []
    served.sni_callback = lambda _socket, name, _context: named.append(name)
    trusted = ssl.create_default_context(cafile=str(ca))
    monkeypatch.setattr(egress, "RESOLVE", Resolver(PUBLIC))
    with receiving(201, tls=served) as (seen, port):
        network = Loopback(port)
        with egress.guarded_client(backend=network, ssl_context=trusted) as client:
            answer = client.post(f"https://localhost:{port}/alerts", content=b"{}")
            with pytest.raises(httpx.ConnectError):
                client.post(f"https://receiver.example:{port}/alerts", content=b"{}")
    assert answer.status_code == 201 and seen == ["/alerts"]
    assert network.attempts == [PUBLIC, PUBLIC]
    assert named == ["localhost", "receiver.example"]


def test_fd12_a_send_that_trickles_is_cut_off_at_its_deadline():
    """Each byte comes well inside the five-second timeout, so only the whole send's deadline
    stops it; no timeout handed to the network is longer than that deadline. The seconds it
    takes are `tests/test_egress_deadline.py`'s."""
    with trickling() as port:
        network = Loopback(port)
        with egress.guarded_client(backend=network, deadline=1.5) as client:
            with pytest.raises(httpx.TimeoutException):
                client.post(f"http://127.0.0.1:{port}/alerts", content=b"{}")
    assert network.attempts == ["127.0.0.1"] and within(network.timeouts, 1.5)


def test_fd12_a_receiver_that_never_answers_is_cut_off_at_its_deadline(monkeypatch):
    """The receiver takes the request and stays silent. httpx's five-second timeout would let
    each read wait five seconds; every read and write the guard hands the network counts down
    from the send's deadline instead."""
    monkeypatch.setattr(egress, "RESOLVE", Resolver(PUBLIC))
    with stalling() as (port, received):
        network = Loopback(port)
        with egress.guarded_client(backend=network, deadline=1.5) as client:
            with pytest.raises(httpx.ReadTimeout):
                client.post(f"http://receiver.example:{port}/alerts", content=b"{}")
    assert received and network.attempts == [PUBLIC]
    assert within(network.timeouts, 1.5)


def test_fd12_a_tls_receiver_that_never_answers_is_cut_off_at_its_deadline(monkeypatch, tmp_path):
    """The same behind TLS: the stream the handshake upgrades to keeps the send's deadline, so
    no read on it waits httpx's five seconds either."""
    ca, cert, key = mint(tmp_path)
    served = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    served.load_cert_chain(cert, key)
    trusted = ssl.create_default_context(cafile=str(ca))
    monkeypatch.setattr(egress, "RESOLVE", Resolver(PUBLIC))
    with stalling(tls=served) as (port, received):
        network = Loopback(port)
        with egress.guarded_client(backend=network, ssl_context=trusted, deadline=1.5) as client:
            with pytest.raises(httpx.ReadTimeout):
                client.post(f"https://localhost:{port}/alerts", content=b"{}")
    assert received and network.attempts == [PUBLIC]
    assert within(network.timeouts, 1.5)


def test_fd12_the_chat_sender_names_the_refusal(monkeypatch):
    monkeypatch.setattr(egress, "RESOLVE", Resolver("10.0.0.7"))
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        result = send_chat(
            "slack", "https://chat.example/services/T0/B0/x", uuid4(), approval(), client
        )
    assert result == SendResult(False, "DESTINATION_NOT_PUBLIC") and network.attempts == []


RECEIVER = LocalReceiver("http://127.0.0.1:8200/alerts", "k" * 32)


class Unread(httpx.SyncByteStream):
    """A response body that records whether anything read it."""

    def __init__(self) -> None:
        self.read = False

    def __iter__(self) -> Iterator[bytes]:
        self.read = True
        yield b"x" * 4096


def answering_with(
    status: int,
    calls: list[httpx.Request] | None = None,
    body: httpx.SyncByteStream | None = None,
    **headers: str,
):
    def handle(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        return httpx.Response(status, headers=headers, stream=body or httpx.ByteStream(b""))

    return httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False)


@pytest.mark.parametrize("status", [200, 201, 202, 204])
def test_fd12_each_accepted_status_is_delivered_by_both_senders(status):
    with answering_with(status) as client:
        assert post_signed(RECEIVER, uuid4(), b"{}", client) == DELIVERED
        assert send_notification(RECEIVER, uuid4(), b"{}", client) is True


@pytest.mark.parametrize("status,delivered", [(200, True), (204, True), (201, False), (202, False)])
def test_fd12_the_export_set_counts_only_200_and_204(status, delivered):
    with answering_with(status) as client:
        sent = send_notification(RECEIVER, uuid4(), b"{}", client, accepted=EXPORT_ACCEPTED)
    assert sent is delivered


@pytest.mark.parametrize(
    "status,expected",
    [
        (429, SendResult(False, "RECEIVER_RATE_LIMITED", 40)),
        (404, SendResult(False, "RECEIVER_REFUSED")),
        (302, SendResult(False, "RECEIVER_UNAVAILABLE")),
        (500, SendResult(False, "RECEIVER_UNAVAILABLE")),
    ],
)
def test_fd12_every_other_status_has_its_code(status, expected):
    with answering_with(status, **{"Retry-After": "40"}) as client:
        assert post_signed(RECEIVER, uuid4(), b"{}", client) == expected
        assert send_notification(RECEIVER, uuid4(), b"{}", client) is False


def test_fd12_no_response_body_is_ever_read():
    for status in (200, 500):
        body = Unread()
        with answering_with(status, body=body) as client:
            post_signed(RECEIVER, uuid4(), b"{}", client)
        assert body.read is False, status


def test_fd12_no_redirect_is_followed():
    """The client here follows redirects, so only the sender's own refusal to follow one keeps
    the request from going on to the address the receiver names."""
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=True) as client:
        assert post_signed(RECEIVER, uuid4(), b"{}", client) == SendResult(
            False, "RECEIVER_UNAVAILABLE"
        )
    assert len(calls) == 1


def test_fd12_a_receiver_that_cannot_be_reached_is_unavailable_not_refused():
    """A connection the network refuses is an ordinary failed attempt; only the guard's own
    refusal is `DESTINATION_NOT_PUBLIC`."""

    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        assert post_signed(RECEIVER, uuid4(), b"{}", client) == SendResult(
            False, "RECEIVER_UNAVAILABLE"
        )


def test_fd12_an_oversize_body_is_refused_before_any_request():
    calls: list[httpx.Request] = []
    with answering_with(204, calls) as client, pytest.raises(MonitorError) as refused:
        post_signed(RECEIVER, uuid4(), b"x" * 4097, client)
    assert refused.value.code == "INVALID_NOTIFICATION" and calls == []


def test_fd12_the_webhook_sender_names_the_refusal(monkeypatch):
    monkeypatch.setattr(egress, "RESOLVE", Resolver("169.254.169.254"))
    named = SimpleNamespace(url="https://receiver.example/alerts", secret="k" * 32)
    network = Loopback()
    with egress.guarded_client(backend=network) as client:
        assert post_signed(named, uuid4(), b"{}", client) == SendResult(
            False, "DESTINATION_NOT_PUBLIC"
        )
    assert network.attempts == []


def test_fd12_the_chat_sender_posts_what_it_is_given_and_never_reads_the_answer():
    calls: list[httpx.Request] = []
    body = Unread()
    with answering_with(200, calls, body=body) as client:
        result = post_chat(
            "slack", "http://127.0.0.1:9/services/T0/B0/x", uuid4(), b'{"text":"x"}', client
        )
    assert result == DELIVERED and calls[0].content == b'{"text":"x"}'
    assert body.read is False


def test_fd12_httpx_logs_a_request_by_its_origin_alone():
    """httpx logs every request it sends at INFO, with the request's whole URL. A Slack or Teams
    destination's path and query are its secret, and no log line carries a destination's URL
    (#31), so the line keeps the method, the origin and the status, never the userinfo, the
    path or the query."""
    lines: list[str] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    logger, handler = logging.getLogger("httpx"), Keep(logging.DEBUG)
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        with receiving(200) as (seen, port), egress.guarded_client() as client:
            path = "/services/T0/B0/secret-path"
            url = f"http://user:pass@127.0.0.1:{port}{path}?q=1"
            assert client.post(url, content=b"{}").status_code == 200
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
    assert seen == [f"{path}?q=1"]
    [line] = [line for line in lines if line.startswith("HTTP Request:")]
    assert line.startswith(f"HTTP Request: POST http://127.0.0.1:{port} ") and "200" in line
    logged = "\n".join(lines)
    for private in ("user", "pass", "@", "secret-path", "/services", "q=1", "?"):
        assert private not in logged, private


def test_fd12_the_httpx_log_filter_never_raises_and_withholds_a_url_it_cannot_cut():
    """A logging filter that raised would fail the request httpx was logging, so the filter never
    raises. A record whose URL it cannot cut keeps its line, so it still shows that a request
    happened, with the URL withheld: a URL can carry a destination's secret in its path."""

    class Broken(httpx.URL):
        @property
        def netloc(self) -> bytes:
            raise RuntimeError("Synthetic failure inside the filter")

    record = logging.LogRecord(
        "httpx",
        logging.INFO,
        __file__,
        1,
        "HTTP Request: %s %s",
        ("POST", Broken("http://127.0.0.1:9/alerts")),
        None,
    )
    assert egress._OriginOnly().filter(record) is True
    said = record.getMessage()
    assert said.startswith("HTTP Request:")
    for private in ("/alerts", "127.0.0.1", ":9"):
        assert private not in said, private
    # Through httpx's own logger, a handler sees the line and nothing of the URL.
    lines: list[str] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    logger, handler = logging.getLogger("httpx"), Keep(logging.DEBUG)
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        logger.info("HTTP Request: %s %s", "POST", Broken("http://127.0.0.1:9/secret-path"))
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
    [line] = lines
    assert line.startswith("HTTP Request:")
    for private in ("secret-path", "127.0.0.1", ":9"):
        assert private not in line, private
