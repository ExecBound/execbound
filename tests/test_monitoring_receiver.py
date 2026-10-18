# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the actual loopback receiver, including signature and duplicate handling."""

import hashlib
import hmac
from threading import Thread
from uuid import uuid4

import httpx

from execbound.monitoring.receiver import make_receiver


def test_receiver_authenticates_and_deduplicates_exact_payload(tmp_path):
    server = make_receiver(0, "k" * 32, tmp_path)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/alerts"
        delivery = str(uuid4())
        payload = b'{"finding":"synthetic"}'
        headers = {
            "Content-Type": "application/json",
            "X-ExecBound-Delivery": delivery,
            "X-ExecBound-Signature": hmac.new(
                b"k" * 32, delivery.encode() + b"\n" + payload, hashlib.sha256
            ).hexdigest(),
        }
        with httpx.Client(trust_env=False) as client:
            assert client.post(url, content=payload, headers=headers).status_code == 204
            assert client.post(url, content=payload, headers=headers).status_code == 204
            assert (
                client.post(
                    url, content=payload, headers=headers | {"X-ExecBound-Delivery": str(uuid4())}
                ).status_code
                == 401
            )
            assert (
                client.post(
                    url, content=payload, headers=headers | {"X-ExecBound-Signature": "bad"}
                ).status_code
                == 401
            )
            different = b'{"finding":"different"}'
            changed = headers | {
                "X-ExecBound-Signature": hmac.new(
                    b"k" * 32, delivery.encode() + b"\n" + different, hashlib.sha256
                ).hexdigest()
            }
            assert client.post(url, content=different, headers=changed).status_code == 409
        assert len(list(tmp_path.glob("*.json"))) == 1
        assert (tmp_path / (delivery + ".json")).read_bytes() == payload
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
