# SPDX-License-Identifier: AGPL-3.0-only
"""Chromium that never hears of a change to the host's network.

Chromium on Linux watches every interface address on the machine over netlink and treats any
address added or removed, on any interface, as a change of network: it flushes its socket
pools with `net::ERR_NETWORK_CHANGED`, failing every request in flight, loopback included
(Chromium's `net/base/address_tracker_linux.cc` and
`net/socket/transport_client_socket_pool.cc`). Nothing on its command line turns that off. On a
host that runs other jobs, Docker gives each new bridge network an IPv4 address and each
container's veth an IPv6 link-local one, so a container started or stopped anywhere on the
machine failed the requests of every browser on it. That was the browser suite's commonest
rerun (#746).

Chromium learns of those changes in one place: its address tracker binds a `NETLINK_ROUTE`
socket with `nl_groups` naming the IPv4 and IPv6 address groups, the link group and the notify
group, and the kernel then sends that socket every change. `launched(browser_type)` starts
Chromium with `LD_PRELOAD` naming a small library, built once per test process from `SOURCE`
below with the host's C compiler. The library wraps `bind()`: for a `NETLINK_ROUTE` socket it
clears `nl_groups`, so the socket joins no group, and it passes every other call through
unchanged. The tracker still reads the interfaces once, through a unicast dump, so the browser
starts with the machine's real connection; it never learns that anything changed afterwards.

After the launch the fixture reads the browser's own sockets in `/proc/net/netlink`. If one of
its route sockets still belongs to a group, the library did not take, and a
`BrowserIsolationWarning` says so, so a future Chromium that subscribes another way cannot undo
this quietly. Where there is no C compiler, or the host is not Linux, the browser starts as
before with the same warning, and the missing protection stays visible in the warnings summary.

#750 first ran the browser in a network namespace of its own instead. The runners' host
restricts unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns`), so it
never took effect there. This needs no privilege.
"""

import atexit
import contextlib
import functools
import os
import shutil
import subprocess
import sys
import tempfile
import time
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from playwright.sync_api import Browser, BrowserType

SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>

/* bind() as libc has it, except that a NETLINK_ROUTE socket joins no multicast group. */
int bind(int fd, const struct sockaddr *address, socklen_t length) {
    static int (*real)(int, const struct sockaddr *, socklen_t);
    if (!real) {
        real = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "bind");
    }
    if (address && length >= sizeof(struct sockaddr_nl) && address->sa_family == AF_NETLINK) {
        int protocol = -1;
        socklen_t size = sizeof(protocol);
        if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &size) == 0
            && protocol == NETLINK_ROUTE) {
            struct sockaddr_nl quiet;
            memcpy(&quiet, address, sizeof(quiet));
            quiet.nl_groups = 0;
            return real(fd, (const struct sockaddr *)&quiet, sizeof(quiet));
        }
    }
    return real(fd, address, length);
}
"""
# `/proc/net/netlink`'s protocol column for a route socket, NETLINK_ROUTE.
ROUTE = "0"
# How long to look for the browser's route socket after the launch. It is there at once on
# the headless shell, which opens it as it starts.
CONFIRM_SECONDS = 5.0


class BrowserIsolationWarning(UserWarning):
    """Chromium may still hear of host network changes; say why."""


@functools.cache
def _library() -> tuple[str | None, str | None]:
    """The built library's path, or None and the reason it could not be built."""
    if not sys.platform.startswith("linux"):
        return None, "the host is not Linux"
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        return None, "no C compiler to build the netlink library"
    directory = tempfile.mkdtemp(prefix="eb-netlink-")
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    source = Path(directory) / "netlink_quiet.c"
    library = Path(directory) / "netlink_quiet.so"
    source.write_text(SOURCE, encoding="utf-8")
    built = subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", "-o", str(library), str(source), "-ldl"],
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        detail = built.stderr.strip().splitlines()
        return None, "the netlink library did not build: " + (detail[-1] if detail else "")
    return str(library), None


def _descendants(root: int) -> list[int]:
    found: list[int] = []
    frontier = [root]
    while frontier:
        pid = frontier.pop()
        found.append(pid)
        with contextlib.suppress(OSError):
            for task in os.listdir(f"/proc/{pid}/task"):
                children = Path(f"/proc/{pid}/task/{task}/children").read_text("ascii")
                frontier.extend(int(child) for child in children.split())
    return found


def route_groups(root: int) -> list[int]:
    """The multicast groups of every route socket held by `root` and its descendants."""
    sockets: dict[str, int] = {}
    for line in Path("/proc/net/netlink").read_text("ascii").splitlines()[1:]:
        fields = line.split()
        if fields[1] == ROUTE:
            sockets[fields[-1]] = int(fields[3], 16)
    groups = []
    for pid in _descendants(root):
        try:
            descriptors = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{descriptor}")
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in sockets:
                groups.append(sockets[target[8:-1]])
    return groups


def _confirm() -> str | None:
    """Why the browser this process launched may still hear of changes, or None if it cannot."""
    deadline = time.monotonic() + CONFIRM_SECONDS
    while True:
        groups = route_groups(os.getpid())
        if groups:
            joined = sorted({group for group in groups if group})
            if joined:
                return "a route socket still joins groups " + ", ".join(f"{g:#x}" for g in joined)
            return None
        if time.monotonic() >= deadline:
            return "no route socket was found to confirm the netlink library took"
        time.sleep(0.1)


@contextlib.contextmanager
def launched(browser_type: BrowserType, **options: Any) -> Iterator[Browser]:
    """Launch Chromium deaf to host network changes, or as before with a warning saying why."""
    library, reason = _library()
    if library is not None:
        environment = dict(options.pop("env", None) or os.environ)
        preload = environment.get("LD_PRELOAD")
        environment["LD_PRELOAD"] = f"{library} {preload}" if preload else library
        options["env"] = environment
    browser = browser_type.launch(**options)
    try:
        if library is not None:
            reason = _confirm()
        if reason is not None:
            warnings.warn(f"browser isolation: {reason}", BrowserIsolationWarning, stacklevel=3)
        yield browser
    finally:
        browser.close()
