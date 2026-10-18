# SPDX-License-Identifier: AGPL-3.0-only
"""Outbound HTTP to a destination the private configuration names, held to public addresses.

A destination's URL is operator configuration, never tenant data, but its host's DNS answer
is not: a receiver whose name is pointed at 10.0.0.5, 127.0.0.1 or 169.254.169.254 would turn
the drain into a request from inside the deployment's own network (THREAT_MODEL.md T6.4). Every
connection this client opens resolves its host once and refuses it unless every address it
resolved is public, counting the IPv4 address an IPv6 address carries. It then connects to an
address it checked, trying the first `MAX_ADDRESSES` in the resolver's order, so no second
answer can be swapped in between the check and the connection. The TLS name is still the URL's
host, so a certificate is verified against the name the operator wrote. A URL whose host is
itself a loopback literal is the one exception: the local test receiver and the test fakes
listen there, and no DNS answer is involved. There is no opt-in for private networks (#31,
decision 7).

Keep-alive is off, so every send opens its own connection, is checked again, and runs inside
one `SEND_DEADLINE`: httpx's timeout bounds each connect, read and write alone, and a server
that trickles its answer a byte at a time would otherwise hold a drain for as long as it likes.
The lookup counts against the same deadline, because `getaddrinfo` takes no timeout and a slow
nameserver can hold it for half a minute, past a drain's lease. No proxy from the environment is
used and no redirect is followed.

httpx logs every request it sends with the request's whole URL, and a Slack or Teams
destination's path and query are its secret, so every URL httpx's own log records name is cut to
its origin before any handler sees it.
"""

import ipaddress
import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any

import httpcore
import httpx

Resolver = Callable[..., list[tuple[Any, ...]]]
# Read at each connection, so a test can stand a fixed answer in for DNS.
RESOLVE: Resolver = socket.getaddrinfo
NOT_PUBLIC = "DESTINATION_NOT_PUBLIC"
# How many of a name's addresses one send tries, in the resolver's order.
MAX_ADDRESSES = 3
# The most one send takes, connect to last byte read, in seconds.
SEND_DEADLINE = 10.0
NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Global unicast IPv6 (RFC 4291). The rest of the space is reserved, unallocated or special
# purpose, and `ipaddress` still calls much of it global (`4000::1`, `fe00::1` and most of
# `::/8` among it). An IPv6 address that carries no IPv4 address must fall inside this. One
# that carries one is judged by itself and what it carries instead, because NAT64 and the
# IPv4-carrying forms in `::/8` lie outside it, and `is_reserved` would refuse them all,
# public or not.
GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
# IPv4-translated addresses (SIIT, RFC 2765), `::ffff:0:a.b.c.d`, which `ipaddress` also calls
# global whatever they carry.
TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")


class _OriginOnly(logging.Filter):
    """httpx logs each request it sends at INFO, naming the request's whole URL. No log line
    carries a destination's URL (#31), whose path and query can be its secret, as a Slack or
    Teams webhook's are: each URL a record of httpx's names is cut to its scheme, host and port,
    so the line keeps the method, the origin and the status. A URL's userinfo is not part of
    its origin and is cut with the rest. A filter that raised would fail the request httpx was
    logging, so whatever goes wrong here keeps the line, which still says a request happened,
    and withholds its URL rather than let one through that may carry a secret."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    f"{item.scheme}://{item.netloc.decode('ascii')}"
                    if isinstance(item, httpx.URL)
                    else item
                    for item in record.args
                )
        except Exception:
            # Never re-raised: a logging filter must not fail the request it logs.
            record.msg, record.args = "HTTP Request: URL withheld", ()
        return True


# On httpx's own logger, once, at import: a logger's filter runs before any handler, its own or
# an ancestor's, sees the record. It covers every client in the process, since it only ever
# removes what a line would otherwise carry.
logging.getLogger("httpx").addFilter(_OriginOnly())


class EgressRefused(httpcore.ConnectError):
    """A host that resolved to an address that is not public; no connection was opened."""


def _carried(found: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """The IPv4 addresses an IPv6 address carries: mapped, NAT64, IPv4-translated, 6to4, Teredo
    (its server and its client) or IPv4-compatible. `ipaddress` calls a NAT64, an
    IPv4-translated or an IPv4-compatible address global whatever it carries, so each is
    checked for what it carries too."""
    carried: list[ipaddress.IPv4Address] = []
    if found.ipv4_mapped is not None:
        carried.append(found.ipv4_mapped)
    if found in NAT64 or found in TRANSLATED:
        carried.append(ipaddress.IPv4Address(int(found) & 0xFFFFFFFF))
    # Defence in depth: Python 3.13 already counts 6to4 (`2002::/16`) and all of `2001::/23`,
    # Teredo's `2001::/32` among it, as not global, so neither form reaches here as public.
    if found.sixtofour is not None:
        carried.append(found.sixtofour)
    if found.teredo is not None:
        carried.extend(found.teredo)
    if int(found) >> 32 == 0:
        carried.append(ipaddress.IPv4Address(int(found)))
    return carried


def public(address: str) -> bool:
    """Whether an address, and every IPv4 address it carries, is one the public internet
    routes: not private, loopback, link-local, shared (100.64.0.0/10), reserved or unspecified,
    and not multicast, which `ipaddress` counts as global. An IPv6 address that carries no IPv4
    address must also be global unicast (`2000::/3`), which refuses the unallocated space and
    the deprecated site-local `fec0::/10` that `ipaddress` calls global."""
    found = ipaddress.ip_address(address)
    checked: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [found]
    if isinstance(found, ipaddress.IPv6Address):
        carried = _carried(found)
        if not carried and found not in GLOBAL_UNICAST:
            return False
        checked.extend(carried)
    return all(item.is_global and not item.is_multicast for item in checked)


def _resolve(host: str, port: int, wait: float) -> list[tuple[Any, ...]]:
    """`RESOLVE`'s answer for `host`, waited for no longer than `wait` seconds. `getaddrinfo`
    takes no timeout, so the lookup runs on a daemon thread that is left behind, not joined,
    once the send's deadline has passed; whatever it answers then is dropped. What a lookup
    raises is the receiver being unavailable: an `OSError` from the resolver as much as a
    `UnicodeError` from a name the IDNA codec cannot encode, or another `ValueError`, and
    nothing of it is quoted. Anything else is a programming error, left to the thread's
    `excepthook`, which reports it; the send then fails as a lookup that never answered."""
    resolver = RESOLVE
    outcome: list[list[tuple[Any, ...]] | OSError | ValueError] = []

    def lookup() -> None:
        try:
            outcome.append(resolver(host, port, type=socket.SOCK_STREAM))
        except (OSError, UnicodeError, ValueError) as error:  # handed to the sender's thread
            outcome.append(error)

    thread = threading.Thread(target=lookup, name="egress-resolve", daemon=True)
    thread.start()
    thread.join(max(wait, 0))
    if not outcome:
        raise httpcore.ConnectTimeout("RECEIVER_UNAVAILABLE")
    answer = outcome[0]
    if isinstance(answer, OSError | ValueError):
        raise httpcore.ConnectError("RECEIVER_UNAVAILABLE") from None
    return answer


def _loopback_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _Deadlined(httpcore.NetworkStream):
    """A connection whose every handshake, read and write counts down from one deadline.

    Each call is handed the deadline left, never more. httpcore's write loop gives each socket
    call that bound afresh, which cannot stretch a send materially: a request here is a few
    hundred bytes of headers and a body of at most 4 KiB, which the socket buffer takes in one
    call, and the TLS handshake and each read are bounded as a whole duration, not per call.
    """

    def __init__(
        self, stream: httpcore.NetworkStream, deadline: float, clock: Callable[[], float]
    ) -> None:
        self._stream, self._deadline, self._clock = stream, deadline, clock

    def _left(self, timeout: float | None, error: type[httpcore.TimeoutException]) -> float:
        left = self._deadline - self._clock()
        if left <= 0:
            raise error("SEND_DEADLINE")
        return left if timeout is None else min(timeout, left)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._stream.read(max_bytes, self._left(timeout, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._stream.write(buffer, self._left(timeout, httpcore.WriteTimeout))

    def close(self) -> None:
        self._stream.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._stream.start_tls(
            ssl_context, server_hostname, self._left(timeout, httpcore.ConnectTimeout)
        )
        return _Deadlined(stream, self._deadline, self._clock)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _Guard(httpcore.NetworkBackend):
    def __init__(self, backend: httpcore.NetworkBackend | None, deadline: float) -> None:
        self._backend = backend or httpcore.SyncBackend()
        self._deadline = deadline

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        deadline = time.monotonic() + self._deadline
        if _loopback_literal(host):
            addresses = [host]
        else:
            answers = _resolve(host, port, deadline - time.monotonic())
            # The resolver's order, each address once.
            found = list(dict.fromkeys(str(answer[4][0]) for answer in answers))
            if not found or not all(public(item) for item in found):
                raise EgressRefused(NOT_PUBLIC)
            addresses = found[:MAX_ADDRESSES]
        failure: Exception | None = None
        for address in addresses:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            try:
                stream = self._backend.connect_tcp(
                    address,
                    port,
                    timeout=left if timeout is None else min(timeout, left),
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as error:
                failure = error
                continue
            return _Deadlined(stream, deadline, time.monotonic)
        raise httpcore.ConnectError("RECEIVER_UNAVAILABLE") from failure

    def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[Any] | None = None
    ) -> httpcore.NetworkStream:
        raise EgressRefused(NOT_PUBLIC)

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


class _Transport(httpx.HTTPTransport):
    def __init__(
        self,
        backend: httpcore.NetworkBackend | None,
        ssl_context: ssl.SSLContext | None,
        deadline: float,
    ) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context or httpx.create_ssl_context(trust_env=False),
            max_keepalive_connections=0,
            network_backend=_Guard(backend, deadline),
        )


def guarded_client(
    *,
    timeout: float = 5,
    backend: httpcore.NetworkBackend | None = None,
    ssl_context: ssl.SSLContext | None = None,
    deadline: float = SEND_DEADLINE,
) -> httpx.Client:
    """The one client both notification drains send through. `backend`, `ssl_context` and
    `deadline` are a test's: a stand-in for the network behind the guard, a trust store that
    holds a CA it minted, and a shorter deadline."""
    return httpx.Client(
        transport=_Transport(backend, ssl_context, deadline),
        trust_env=False,
        follow_redirects=False,
        timeout=timeout,
    )


def refused(error: BaseException) -> bool:
    """Whether an `httpx` error was this guard's refusal: httpx keeps httpcore's exception as
    its cause."""
    return isinstance(error.__cause__, EgressRefused)
