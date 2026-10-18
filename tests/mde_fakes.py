# SPDX-License-Identifier: AGPL-3.0-only
"""A fake Defender for Endpoint API and a fake ExecBound gateway, on loopback."""

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self

from conftest import remember_secret


class _Server:
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.state = self  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def _send(handler: BaseHTTPRequestHandler, status: int, body: Any, **headers: str) -> None:
    raw = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    for name, value in headers.items():
        handler.send_header(name.replace("_", "-"), value)
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


class _Defender(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        return

    def do_POST(self) -> None:
        state: FakeDefender = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", "0"))
        state.token_requests.append(self.rfile.read(length).decode())
        if state.token_status != 200:
            _send(self, state.token_status, {"error": "invalid_client"})
            return
        if state.redirect_token:
            _send(self, 307, {}, Location=state.redirect_token)
            return
        _send(
            self,
            200,
            state.token_answer or {"access_token": state.token, "expires_in": state.expires_in},
        )

    def do_GET(self) -> None:
        state: FakeDefender = self.server.state  # type: ignore[attr-defined]
        state.reads.append(self.path)
        if state.redirect_read:
            _send(self, 302, {}, Location=state.redirect_read)
        elif self.headers.get("Authorization") != "Bearer " + state.token:
            _send(self, 401, {"error": "unauthorized"})
        elif state.throttle:
            _send(self, 429, {"error": "throttled"}, Retry_After="7")
        elif self.path not in state.pages:
            _send(self, 404, {"error": "not found"})
        else:
            _send(self, 200, state.pages[self.path])


class FakeDefender(_Server):
    def __init__(self, machines: list[dict[str, Any]]) -> None:
        super().__init__(_Defender)
        self.token_requests: list[str] = []
        self.reads: list[str] = []
        self.token_status = 200
        self.expires_in = 3599
        self.throttle = False
        self.token = remember_secret(secrets.token_urlsafe(40))
        self.token_answer = None
        self.redirect_token = None
        self.redirect_read = None
        self.pages: dict[str, dict[str, Any]] = {"/api/machines": {"value": machines}}


class _Gateway(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        return

    def do_POST(self) -> None:
        state: FakeGateway = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        state.posts.append((self.headers.get("Authorization", ""), body))
        if state.redirect:
            _send(self, 302, {}, Location=state.redirect)
            return
        status, code = state.answer
        _send(self, status, {"code": code} if code else {"duplicate": status == 200})


class FakeGateway(_Server):
    def __init__(self) -> None:
        super().__init__(_Gateway)
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.answer: tuple[int, str | None] = (202, None)
        self.redirect = None


class _Raw(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        return

    def do_GET(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        self.wfile.write(state.responses.pop(0))
        self.close_connection = True

    do_POST = do_GET


class RawHTTP(_Server):
    """An HTTP peer that emits incomplete or malformed protocol bytes."""

    def __init__(self, *responses: bytes) -> None:
        super().__init__(_Raw)
        self.responses = list(responses)


def machine(
    machine_id: str, *, resource: str | None, risk: object = "Medium", **extra: Any
) -> dict[str, Any]:
    """A machine as Defender returns it, with the fields the producer must drop."""
    return {
        "id": machine_id,
        "computerDnsName": f"{machine_id}.lab",
        "riskScore": risk,
        "healthStatus": "Active",
        "vmMetadata": None if resource is None else {"resourceId": resource, "vmId": "v"},
        "ipAddresses": [{"ipAddress": "10.47.0.5"}],
        "aadDeviceId": "d",
        "machineTags": ["lab"],
        **extra,
    }
