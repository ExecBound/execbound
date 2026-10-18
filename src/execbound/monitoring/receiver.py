# SPDX-License-Identifier: AGPL-3.0-only
"""Development-only authenticated loopback receiver with durable duplicate detection."""

import hashlib
import hmac
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from uuid import UUID


def make_receiver(port: int, secret: str, output: Path) -> ThreadingHTTPServer:
    if not 0 <= port <= 65535 or not 32 <= len(secret) <= 256 or not secret.isascii():
        raise ValueError("Invalid local receiver configuration")
    output.mkdir(parents=True, exist_ok=True)
    lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, format: str, *args: object) -> None:
            # No HTTP request strings, headers or credentials enter diagnostics.
            pass

        def finish_response(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self) -> None:
            try:
                lengths = self.headers.get_all("Content-Length", [])
                deliveries = self.headers.get_all("X-ExecBound-Delivery", [])
                signatures = self.headers.get_all("X-ExecBound-Signature", [])
                if (
                    self.path != "/alerts"
                    or len(lengths) != 1
                    or len(deliveries) != 1
                    or len(signatures) != 1
                    or "Transfer-Encoding" in self.headers
                    or "Content-Encoding" in self.headers
                    or not 0 < int(lengths[0]) <= 1_048_576
                    or str(UUID(deliveries[0])) != deliveries[0]
                ):
                    raise ValueError
                payload = self.rfile.read(int(lengths[0]))
                if len(payload) != int(lengths[0]):
                    raise ValueError
                digest = hmac.new(
                    secret.encode("ascii"),
                    deliveries[0].encode("ascii") + b"\n" + payload,
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(digest.encode(), signatures[0].encode()):
                    self.finish_response(401)
                    return
                destination = output / (deliveries[0] + ".json")
                # One owner serializes identical delivery IDs; the ack follows fsync.
                with lock:
                    if destination.exists():
                        identical = destination.read_bytes() == payload
                        self.finish_response(204 if identical else 409)
                        return
                    if len(list(output.glob("*.json"))) >= 10000:
                        self.finish_response(503)
                        return
                    temporary = output / (deliveries[0] + ".pending")
                    with temporary.open("wb") as handle:
                        handle.write(payload)
                        handle.flush()
                        os.fsync(handle.fileno())
                    temporary.replace(destination)
                self.finish_response(204)
            except (ValueError, OSError):
                self.finish_response(400)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
