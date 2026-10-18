# SPDX-License-Identifier: AGPL-3.0-only
"""A local fake of the Tines management API for collector tests.

Serves recorded response *shapes* over loopback so the collector's real URL building,
headers, pagination, status handling and response bounds run against a socket. It never
contacts a vendor and holds only synthetic records. Tests reach it through
:func:`transport`, which rewrites the pinned ``https://`` origin onto the loopback port,
so the collector keeps its real origin pin instead of being handed a test URL.
"""

import json
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

# The fake answers for this origin only; it is a synthetic tenant, never a real one.
BASE_URL = "https://fixture.tines.com"

STORIES_PATH = "/api/v1/stories"
ACTIONS_PATH = "/api/v1/actions"
CREDENTIALS_PATH = "/api/v1/user_credentials"
AUDIT_PATH = "/api/v1/audit_logs"


@dataclass
class Scenario:
    """Records and failure modes one fake tenant serves."""

    stories: list[dict[str, Any]] = field(default_factory=list)
    actions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    tenant_id: int = 900
    # The vendor caps per_page server side; a small cap forces the pagination walk.
    max_per_page: int = 100
    # Endpoint key ("stories", "actions", "credentials", "audit") to a forced status code.
    status: dict[str, int] = field(default_factory=dict)
    # Endpoint keys the tenant's plan excludes; answered the way the vendor answers, with
    # 422 and a message body, verified against a live Community Edition tenant.
    gated: frozenset[str] = frozenset()
    retry_after: str | None = None
    # Bytes of filler added to every story record, to exercise the response size bound.
    padding: int = 0


class _Handler(BaseHTTPRequestHandler):
    server: "FakeTines"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # pragma: no cover - keep test output clean
        return

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        query = {key: values[-1] for key, values in parse_qs(url.query).items()}
        self.server.requests.append((url.path, dict(query), dict(self.headers)))
        scenario = self.server.scenario
        key, records = self.server.records(url.path)
        if key is None:
            self._send(404, {"error": "not found"})
            return
        if key in scenario.gated:
            self._send(
                422,
                [
                    "This feature (AUDIT_LOGS) is not enabled on this tenant. "
                    "Please contact support to upgrade your plan"
                ],
            )
            return
        forced = scenario.status.get(key)
        if forced is not None:
            headers = {}
            if forced == 429 and scenario.retry_after is not None:
                headers["Retry-After"] = scenario.retry_after
            self._send(forced, {"error": "forced"}, headers)
            return
        if key == "actions":
            story = query.get("story_id")
            if story is not None:
                records = [r for r in records if str(r.get("story_id")) == story]
        if key == "audit":
            after = query.get("after")
            if after:
                records = [r for r in records if r["created_at"] > after]
            names = parse_qs(url.query).get("operation_name[]")
            if names:
                records = [r for r in records if r["operation_name"] in set(names)]
        try:
            page = int(query.get("page", "1"))
            per_page = min(int(query.get("per_page", "20")), scenario.max_per_page)
        except ValueError:
            self._send(400, {"error": "invalid page"})
            return
        if page < 1 or per_page < 1:
            self._send(400, {"error": "invalid page"})
            return
        pages = max(1, -(-len(records) // per_page))
        window = records[(page - 1) * per_page : page * per_page]
        if scenario.padding and key == "stories":
            window = [{**r, "description": "x" * scenario.padding} for r in window]
        self._send(
            200,
            {
                self.server.envelope(key): window,
                "meta": {
                    "current_page": page,
                    "previous_page": page - 1 if page > 1 else None,
                    "next_page": page + 1 if page < pages else None,
                    "per_page": per_page,
                    "pages": pages,
                    "count": len(records),
                },
            },
        )

    def _send(self, status: int, body: object, headers: Mapping[str, str] = {}) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)


class FakeTines(ThreadingHTTPServer):
    """One synthetic Tines tenant on loopback."""

    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[tuple[str, dict[str, str], dict[str, str]]] = []

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def records(self, path: str) -> tuple[str | None, Sequence[dict[str, Any]]]:
        if path == STORIES_PATH:
            return "stories", self.scenario.stories
        if path == ACTIONS_PATH:
            # One flat collection, exactly as the tenant serves it.
            return "actions", [a for actions in self.scenario.actions.values() for a in actions]
        if path == CREDENTIALS_PATH:
            return "credentials", self.scenario.credentials
        if path == AUDIT_PATH:
            return "audit", self.scenario.audit
        return None, ()

    @staticmethod
    def envelope(key: str) -> str:
        # The vendor's list key per endpoint, verified against a live tenant: an action is
        # still called an "agent" in list responses.
        return {
            "stories": "stories",
            "actions": "agents",
            "credentials": "user_credentials",
            "audit": "audit_logs",
        }[key]

    def paths(self) -> list[str]:
        return [path for path, _, _ in self.requests]


class _Rewriting(httpx.BaseTransport):
    """Send a request built for the pinned origin to the loopback fake instead."""

    def __init__(self, origin: str) -> None:
        self._origin = urlsplit(origin)
        self._inner = httpx.HTTPTransport(trust_env=False, retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != urlsplit(BASE_URL).hostname:
            raise httpx.ConnectError("Unpinned origin")
        request.url = request.url.copy_with(
            scheme=self._origin.scheme, host=self._origin.hostname, port=self._origin.port
        )
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


@contextmanager
def serving(scenario: Scenario) -> Iterator[FakeTines]:
    server = FakeTines(scenario)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def transport(server: FakeTines) -> httpx.BaseTransport:
    return _Rewriting(server.origin)
