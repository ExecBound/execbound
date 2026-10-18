# SPDX-License-Identifier: AGPL-3.0-only
"""The harness every console API test module reuses (#333).

`console_client` signs a person in through the login form, reads the session route once for
the CSRF token, and returns a client whose `post` sends JSON with the token and the exact Origin,
so a module's tests read like the page they cover. `refusals` exercises the refusals every route
must make: a bearer credential (403, audited as `execution.rejected`), no session (401 with a
typed code, JSON even to a browser). `assert_no_secrets` runs the shared secret check over a
response's body and headers. `every_log_line` captures what every logger writes, ExecBound's own
as a deployment writes it. A test module adds its own cases on top; it does not rewrite these.
"""

import io
import json
import logging
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text
from test_human_surface import credential, form_values

from execbound import logging_schema
from execbound.app import create_app
from execbound.replay.verify import reject_secrets
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

ORIGIN = "http://127.0.0.1"
API = "/api/console/v1"


def console_config(**changes: Any) -> HumanConfig:
    keys = TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    return HumanConfig(ORIGIN, keys, **changes)


class ConsoleClient:
    """A signed-in person: GETs carry the cookie; POSTs carry the token, the Origin and JSON."""

    def __init__(self, client: TestClient, csrf: str) -> None:
        self.client = client
        self.csrf = csrf

    def get(self, path: str, **kwargs: Any):
        return self.client.get(path, **kwargs)

    def post(
        self,
        path: str,
        body: Any = None,
        *,
        csrf: str | None = "",
        content_type: str | None = "application/json",
        origin: str | None = ORIGIN,
        raw: bytes | None = None,
    ):
        headers: dict[str, str] = {}
        if origin is not None:
            headers["Origin"] = origin
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf or self.csrf
        if content_type is not None:
            headers["Content-Type"] = content_type
        content = raw if raw is not None else json.dumps(body if body is not None else {}).encode()
        return self.client.post(path, content=content, headers=headers)


def sign_in(client: TestClient, admin_engine, identity) -> ConsoleClient:
    """Sign one person in on a client that already exists, through the login form, and read the
    session route once for the CSRF token. Signing in again replaces the session before."""
    _, values = form_values(client.get("/login").text, "/session")
    values["credential"] = credential(admin_engine, identity)
    assert client.post("/session", data=values, headers={"Origin": ORIGIN}).status_code == 303
    opened = client.get(API + "/session")
    assert opened.status_code == 200, opened.text
    return ConsoleClient(client, opened.json()["csrf_token"])


@contextmanager
def console_client(db, runtime, admin_engine, identity, *, config: HumanConfig | None = None):
    app = create_app(db, runtime=runtime, human=config or console_config())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        yield sign_in(client, admin_engine, identity)


class LogLines:
    """What `every_log_line` captured, in its two halves.

    Called, it is both halves as one text, which is what a sweep for a value reads. `written()` is
    ExecBound's own lines as `SchemaFormatter` writes them, and `handed()` is one line per record
    any logger was handed, with its fields as `record.execbound` carries them. The formatter turns
    anything secret-shaped, an unknown field or another logger's record into `log.suppressed`, so
    only the second half can ever hold what a sweep looks for: `holds` proves each half captured
    an event on its own, so a sweep that finds nothing has read both."""

    def __init__(self, stream: io.StringIO, seen: list[str]) -> None:
        self._stream = stream
        self._seen = seen

    def __call__(self) -> str:
        return self.written() + "\n" + "\n".join(self._seen)

    def written(self) -> str:
        return self._stream.getvalue()

    def handed(self) -> list[str]:
        return list(self._seen)

    def holds(self, event: str, *values: str) -> bool:
        """Whether each half has a line of its own for `event` that holds every one of `values`:
        the formatter's compact JSON in the first, the record's fields as `json.dumps` writes
        them in the second."""
        formatted = json.dumps({"event": event}, separators=(",", ":"))[1:-1]
        raw = json.dumps({"event": event})[1:-1]

        def found(lines: list[str], marker: str) -> bool:
            return any(marker in line and all(value in line for value in values) for line in lines)

        return found(self.written().splitlines(), formatted) and found(self._seen, raw)


@contextmanager
def every_log_line() -> Iterator[LogLines]:
    """Everything logged while it is open, at every level: what ExecBound's own logger writes as
    a deployment writes it (`SchemaFormatter`'s lines), and every record any logger is handed,
    with its message, its arguments, the fields ExecBound's records carry in `record.execbound`
    and any traceback. Enter it after the application is built, because building one installs
    ExecBound's logger at INFO again. A test proves both halves were captured with
    `LogLines.holds` before it sweeps them.

    pytest's `caplog` cannot stand in for it. ExecBound's logger does not propagate and keeps
    INFO, so `caplog.set_level` lowers only the root and a DEBUG record of its never reaches a
    handler; pytest attaches to a logger that does not propagate only if it already did not when
    the test began; and `log_event` puts its fields in `record.execbound`, not the message, so
    `caplog.text` holds none of their values."""
    ours = logging_schema.install()
    stream = io.StringIO()
    written = logging_schema.capture_handler(stream)
    seen: list[str] = []

    class Every(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            fields = json.dumps(getattr(record, "execbound", None), default=str)
            trace = logging.Formatter().formatException(record.exc_info) if record.exc_info else ""
            seen.append(f"{record.name} {record.getMessage()} {fields} {trace}")

    every = Every(logging.DEBUG)
    root = logging.getLogger()
    loggers = [root] + [
        logger
        for logger in logging.Logger.manager.loggerDict.values()
        if isinstance(logger, logging.Logger)
    ]
    levels = {logger: logger.level for logger in loggers}
    for logger in loggers:
        if logger is root or logger.level != logging.NOTSET:
            logger.setLevel(logging.DEBUG)
    # A record reaches the root's handlers unless a logger on its way does not propagate.
    reached = [logger for logger in loggers if logger is root or not logger.propagate]
    ours.addHandler(written)
    for logger in reached:
        logger.addHandler(every)
    try:
        yield LogLines(stream, seen)
    finally:
        ours.removeHandler(written)
        for logger in reached:
            logger.removeHandler(every)
        for logger, level in levels.items():
            logger.setLevel(level)


def assert_no_secrets(response) -> None:
    """The shared secret check over the body and the headers of one response."""
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("application/json") and response.content:
        reject_secrets(response.json())
    else:
        reject_secrets(response.text)
    assert response.headers.get_list("set-cookie") == [], "a console API response set a cookie"


def rejections(admin_engine, identity) -> int:
    """How many `execution.rejected` events one identity has been audited with."""
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND actor_id=:p AND kind='execution.rejected'"
                ),
                {"t": identity.tenant_id, "p": identity.principal_id},
            ).scalar_one()
        )


def refusals(
    db, runtime, seeded, admin_engine, world, path: str, method: str = "GET"
) -> dict[str, Any]:
    """The bearer and the no-session refusals of one route, and how many were audited."""
    app = create_app(db, runtime=runtime, human=console_config())
    before = rejections(admin_engine, world["identity"])
    results: dict[str, Any] = {}
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        bearer = {"Authorization": "Bearer " + seeded["tokens"][0], "Origin": ORIGIN}
        results["bearer"] = (
            client.get(path, headers=bearer)
            if method == "GET"
            else client.post(
                path, content=b"{}", headers={**bearer, "Content-Type": "application/json"}
            )
        )
        browser = {"Accept": "text/html", "Origin": ORIGIN, "Content-Type": "application/json"}
        results["no_session"] = (
            client.get(path, headers=browser)
            if method == "GET"
            else client.post(path, content=b"{}", headers=browser)
        )
    results["audited"] = rejections(admin_engine, world["identity"]) - before
    return results
