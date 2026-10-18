# SPDX-License-Identifier: AGPL-3.0-only
"""FD12's deadlines in seconds: each ends a send within three seconds of a 1.5 s deadline.

`tests/test_egress.py` holds what the egress guard does at its deadline without reading a clock:
a slow lookup is given up before it answers, and no timeout the guard hands the network is
longer than the send's deadline. Those are acceptance evidence on every run. This file holds the
wall-clock seconds each case takes, which is the claim a drain's lease rests on, measured under
the machine's timing lock (`timed_alone`) so another suite's load is not taken for a regression.
It takes that lock, so it is `timed`, and a run that selects `not timed` leaves it out.
"""

import ssl
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
from smtp_double import mint
from test_egress import PUBLIC, Loopback, Resolver, Slow, stalling, trickling

from execbound import egress
from execbound.monitoring.delivery import post_signed
from execbound.transports import SendResult

DEADLINE = 1.5
UNAVAILABLE = SendResult(False, "RECEIVER_UNAVAILABLE")


@pytest.mark.timed
def test_each_egress_deadline_ends_the_send_within_three_seconds(
    monkeypatch, tmp_path, timed_alone
):
    """A lookup that takes three seconds, a receiver that never answers, in the clear and
    behind TLS, and one that trickles its headers: each send through the signed sender ends
    unavailable within three seconds, where httpx's five-second timeout alone would let a
    silent read wait five and a trickle run for as long as the receiver likes. Only the send
    is timed, not the stand-in servers' teardown."""
    ca, cert, key = mint(tmp_path)
    served = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    served.load_cert_chain(cert, key)
    trusted = ssl.create_default_context(cafile=str(ca))
    took: dict[str, tuple[SendResult, float]] = {}

    def send(case: str, url: str, network: Loopback, **options: object) -> None:
        receiver = SimpleNamespace(url=url, secret="k" * 32)
        with egress.guarded_client(backend=network, deadline=DEADLINE, **options) as client:
            began = time.monotonic()
            result = post_signed(receiver, uuid4(), b"{}", client)
            took[case] = (result, time.monotonic() - began)

    with timed_alone("the egress guard's deadlines") as machine:
        slow = Slow(3, PUBLIC)
        monkeypatch.setattr(egress, "RESOLVE", slow)
        try:
            send("a three-second lookup", "https://receiver.example/alerts", Loopback())
        finally:
            slow.release.set()
        monkeypatch.setattr(egress, "RESOLVE", Resolver(PUBLIC))
        with stalling() as (port, _):
            send(
                "a receiver that never answers",
                f"http://receiver.example:{port}/alerts",
                Loopback(port),
            )
        with stalling(tls=served) as (port, _):
            send(
                "a TLS receiver that never answers",
                f"https://localhost:{port}/alerts",
                Loopback(port),
                ssl_context=trusted,
            )
        with trickling() as port:
            send("a receiver that trickles", f"http://127.0.0.1:{port}/alerts", Loopback(port))
    assert len(took) == 4
    for case, (result, elapsed) in took.items():
        assert result == UNAVAILABLE, case
        assert elapsed < 3, f"{case}: {elapsed:.2f} s; {machine.note}"
