# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted local validation harness; never imported by the gateway or offline replay."""

import argparse
import asyncio
import hashlib
import json
import os
import re
import socket

# The harness launches its own gateway/provider processes with fixed argv and no shell.
import subprocess  # nosec B404 - the harness's own processes, fixed argv, no shell
import sys
import sysconfig
import time
import traceback
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import text

from execbound.connection import local_database_url, local_databases
from execbound.db import TABLES, Database
from execbound.identity import authenticate
from execbound.replay.export import export_history, publish_export
from execbound.replay.fixture import run_check
from execbound.replay.runner import read_bounded, run_replay
from execbound.replay.sanitize import run_build

# A column name the fingerprint may quote into its query: the product schema's own lowercase
# identifiers, and nothing a catalog row could carry beyond them.
_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")

# How a service serves. `DemoServices.start` binds the port and hands the listening socket to
# the service by descriptor, so the port is never free between being checked and being
# served; where no socket can be handed over (Windows), the service binds the port itself.
SERVE = r"""
import os
def serve(app, **options):
    import socket
    import uvicorn
    descriptor = os.environ.get('VALIDATION_FD')
    if descriptor is None:
        uvicorn.run(app, host='127.0.0.1', port=int(os.environ['VALIDATION_PORT']), **options)
    else:
        listener = socket.socket(fileno=int(descriptor))
        uvicorn.Server(uvicorn.Config(app, **options)).run(sockets=[listener])
"""

GATEWAY_SCRIPT = (
    SERVE
    + r"""
serve('execbound.app:create_app', factory=True, access_log=False, log_level='error')
"""
)

PROVIDER_SCRIPT = (
    SERVE
    + r"""
from pathlib import Path
from execbound.provider.mock_store import MockStore
from execbound.provider.identity_store import IdentityStore
Store = IdentityStore if os.environ['EXECBOUND_MOCK_PROVIDER']=='mock_entra' else MockStore
original = Store.dispatch
def dispatch(self, command):
    result = original(self, command)
    with open(os.environ['VALIDATION_INVOCATIONS'], 'a') as handle:
        handle.write(str(command.operation_id)+'\n')
    marker = Path(os.environ['VALIDATION_DROP_MARKER'])
    if marker.exists():
        marker.unlink()
        os._exit(0)
    return result
Store.dispatch = dispatch
serve('execbound_connectors.mock_app:create_mock_app', factory=True,
      access_log=False, log_level='error')
"""
)


def private_json(path: Path) -> Any:
    return json.loads(read_bounded(path, 1024 * 1024))


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")


class HarnessError(RuntimeError):
    """A failure this harness words itself, so its message carries no private value."""


_STDLIB = Path(sysconfig.get_paths()["stdlib"]).resolve()


def _origin(failure: BaseException) -> str:
    """Where it failed, by file and line. The deepest standard library frame names the
    mechanism rather than the mistake, so the deepest frame outside it is reported."""

    def ours(frame: traceback.FrameSummary) -> bool:
        if frame.filename.startswith("<"):
            return False
        return not Path(frame.filename).resolve().is_relative_to(_STDLIB)

    frames = traceback.extract_tb(failure.__traceback__)
    named = [frame for frame in frames if ours(frame)] or frames
    return f"{Path(named[-1].filename).name}:{named[-1].lineno}"


@dataclass
class DemoServices:
    private: Path
    fixture: dict[str, Any]
    processes: dict[str, subprocess.Popen[bytes]] = field(default_factory=dict)
    # Listening sockets a caller bound when it chose the ports, held since then so no other
    # process could take one; each is handed to its service on that service's first start.
    listeners: dict[str, socket.socket] = field(default_factory=dict)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.fixture['ports']['gateway']}"

    def stop(self, name: str) -> None:
        process = self.processes.pop(name, None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def start(self, name: str, *, readiness_host: str | None = None) -> None:
        """Start the named service; for ``gateway``, ``readiness_host`` is the ``Host``
        header the readiness probe sends, distinct from the loopback address it connects to.

        The gateway refuses any request whose ``Host`` header does not match its configured
        origin's netloc (``execbound.app``'s ``response_headers`` middleware), which always
        names a `HumanConfig`, since a private configuration file always names an origin. The
        local demo's origin is the same loopback address this probe connects to, so the
        default (no override) reproduces today's behaviour exactly. A gateway fronted by a
        tunnel, so that a hosted workflow engine can reach it, configures a non-loopback
        origin and needs the probe to present that origin's host instead, or the gateway
        answers 400 "Unsupported or ambiguous identity fields" and the probe never succeeds.
        """
        port = self.fixture["ports"][name]
        listener = self.listeners.pop(name, None)
        if listener is None:
            # Bound here and held until the service has its own copy, so no other process
            # can take the port between this check and the service serving it. Reuse closed
            # POSIX sockets in TIME_WAIT while refusing active listeners; create_server keeps
            # reuse_port disabled and avoids Windows SO_REUSEADDR.
            try:
                listener = socket.create_server(("127.0.0.1", port))
            except OSError:
                # Another run on this machine, not a broken harness. A port number names
                # itself safely, so say which listener could not start.
                raise HarnessError(f"{name} port {port} is already in use") from None
        elif listener.getsockname() != ("127.0.0.1", port):
            listener.close()
            raise HarnessError(f"{name} listener is not on port {port}")
        try:
            environment = {**os.environ, "VALIDATION_PORT": str(port)}
            if name == "gateway":
                environment["EXECBOUND_RUNTIME_CONFIG"] = str(self.private / "gateway.json")
                command = [sys.executable, "-c", GATEWAY_SCRIPT]
            else:
                provider = "mock_entra" if name == "identity" else "mock_crowdstrike"
                environment.update(
                    {
                        "EXECBOUND_MOCK_PROVIDER": provider,
                        "EXECBOUND_MOCK_DATABASE_PATH": str(self.private / f"{name}.sqlite3"),
                        "EXECBOUND_MOCK_ACCOUNTS_PATH": str(self.private / f"{name}-accounts.json"),
                        "VALIDATION_INVOCATIONS": str(self.private / f"{name}.invocations"),
                        "VALIDATION_DROP_MARKER": str(self.private / f"{name}.drop-response"),
                    }
                )
                command = [sys.executable, "-c", PROVIDER_SCRIPT]
            flags = 0
            handed: tuple[int, ...] = ()
            if sys.platform == "win32":
                flags = subprocess.CREATE_NO_WINDOW
                # Windows cannot hand a socket over by descriptor, so the service binds the
                # port itself, and the port is free from here until it does.
                listener.close()
            else:
                handed = (listener.fileno(),)
                environment["VALIDATION_FD"] = str(listener.fileno())
            with (self.private / f"{name}.log").open("ab") as log:
                process = subprocess.Popen(  # nosec B603 - fixed argv built above, no shell
                    command,
                    env=environment,
                    stdout=log,
                    stderr=log,
                    creationflags=flags,
                    pass_fds=handed,
                )
        finally:
            # The service holds its own copy now; this one would keep the port listening,
            # queueing connections nobody serves, after the service stops.
            listener.close()
        self.processes[name] = process
        deadline = time.monotonic() + 15
        with httpx.Client(trust_env=False, timeout=0.5) as client:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ValueError("Demo service startup failed")
                try:
                    headers = (
                        {"Host": readiness_host}
                        if name == "gateway" and readiness_host is not None
                        else None
                    )
                    response = client.get(
                        f"http://127.0.0.1:{port}/health/ready"
                        if name == "gateway"
                        else f"http://127.0.0.1:{port}/",
                        headers=headers,
                    )
                    if name != "gateway" or response.status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
        raise ValueError("Demo service startup timed out")


@contextmanager
def services(
    private: Path, listeners: dict[str, socket.socket] | None = None
) -> Iterator[DemoServices]:
    local_database_url(
        os.environ["DATABASE_URL"],
        databases=local_databases(),
        username="execbound_app",
    )
    private = private.resolve(strict=True)
    fixture = private_json(private / "fixture.json")
    ports = fixture["ports"]
    if (
        set(ports) != {"gateway", "endpoint", "identity"}
        or len(set(ports.values())) != 3
        or any(type(port) is not int or not 1024 <= port <= 65535 for port in ports.values())
    ):
        raise ValueError("Invalid demo ports")
    config = private_json(private / "gateway.json")
    if config["origin"] != f"http://127.0.0.1:{ports['gateway']}":
        raise ValueError("Invalid demo origin")
    for connector in config["connectors"]:
        name = {"mock_crowdstrike": "endpoint", "mock_entra": "identity"}[connector["provider"]]
        if connector["origin"] != f"http://127.0.0.1:{ports[name]}":
            raise ValueError("Invalid demo connector")
    running = DemoServices(private, fixture, listeners=dict(listeners or {}))
    try:
        for name in ("endpoint", "identity", "gateway"):
            running.start(name)
        yield running
    finally:
        for name in ("gateway", "identity", "endpoint"):
            running.stop(name)
        for listener in running.listeners.values():
            listener.close()


def action_request(target: dict[str, Any], action: str, key: str) -> dict[str, Any]:
    return {
        "operation_ref": action,
        "target": {"kind": "canonical", "value": target["resource_id"]},
        "arguments": {},
        "idempotency_key": key,
        "claimed_context": {"incident_id": target["incident_id"]},
    }


async def mcp_retry(origin: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token}, trust_env=False
    ) as http:
        async with Client(streamable_http_client(origin + "/mcp/", http_client=http)) as client:
            result = await client.call_tool("execute", {"request": body})
            if result.is_error or result.structured_content is None:
                raise ValueError("MCP validation failed")
            return {"protocol": client.protocol_version, "execution": result.structured_content}


def snapshot(db: Database, tenants: list[dict[str, Any]]) -> str:
    rows = []
    for tenant in tenants:
        with db.transaction(UUID(tenant["tenant_id"])) as conn:
            # The fingerprint is taken as the runtime, so it reads what the runtime can read
            # and nothing is granted for it. A table the runtime can read only in part
            # (`signal_sources`, whose token digests it never holds, 0068) is fingerprinted
            # over the columns it can read: `signal_admit` moves that table's health columns,
            # so skipping it would leave a change there unseen. A table it cannot read at all
            # (a dormant table, 0065, with no plugin loaded) is skipped.
            readable: dict[str, list[str]] = {}
            for relname, attname in conn.execute(
                text(
                    "SELECT c.relname, a.attname FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "JOIN pg_attribute a ON a.attrelid = c.oid "
                    "WHERE n.nspname = 'execbound' AND c.relkind = 'r' "
                    "AND a.attnum > 0 AND NOT a.attisdropped "
                    "AND has_column_privilege(current_user, c.oid, a.attnum, 'SELECT') "
                    "ORDER BY c.relname, a.attnum"
                )
            ):
                if _IDENTIFIER.fullmatch(attname) is None:
                    raise ValueError("Unexpected column name in the product schema")
                readable.setdefault(relname, []).append(attname)
            # table iterates the fixed TABLES tuple; the columns are the catalog's own names
            # for that table, checked above.
            for table in TABLES:
                if table not in readable:
                    continue
                columns = ", ".join(f'"{column}"' for column in readable[table])
                query = (
                    "SELECT count(*),string_agg(md5(to_jsonb(r)::text),',' "
                    "ORDER BY to_jsonb(r)::text) "
                    # The table is from the fixed TABLES tuple and each column is the catalog's
                    # own name for it, checked against _IDENTIFIER above.
                    f"FROM (SELECT {columns} FROM execbound.{table}) r"  # nosec B608 - fixed names
                )
                rows.append(conn.execute(text(query)).one())
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def provider_snapshot(private: Path) -> str:
    import sqlite3

    rows: list[Any] = []
    for name in ("endpoint", "identity"):
        with sqlite3.connect(private / f"{name}.sqlite3") as conn:
            tables = [
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            ]
            for table in sorted(tables):
                # table comes from sqlite_master of the harness's own private store.
                query = 'SELECT * FROM "' + table + '"'  # nosec B608 - the harness's own store
                rows.append(sorted(conn.execute(query).fetchall(), key=repr))
        log = private / f"{name}.invocations"
        rows.append(log.read_bytes() if log.exists() else b"")
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def browser_approve(browser: Any, origin: str, token: str, output: Path, label: str) -> None:
    with browser.new_context(base_url=origin, viewport={"width": 1440, "height": 1000}) as context:
        page = context.new_page()
        page.set_default_timeout(15000)
        page.goto("/login?setup=1")
        page.get_by_label("Setup credential").fill(token)
        page.get_by_role("button", name="Continue setup").click()
        # Signing in lands an approver on the console's Approvals page; the queue lists what
        # is waiting and a row opens its approval beside it (#333).
        page.get_by_role("list", name="Approvals").get_by_role("link").first.click()
        # The button's name begins with its word and goes on to say what it approves (#678).
        approval = page.get_by_role("button", name=re.compile(r"^Approve\b"))
        approval.wait_for()
        # No screenshots of the login page, cookies, tracing or browser storage.
        for suffix, viewport in (
            ("desktop", {"width": 1440, "height": 1000}),
            ("mobile", {"width": 390, "height": 844}),
        ):
            page.set_viewport_size(viewport)
            page.screenshot(path=str(output / f"{label}-{suffix}.png"), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 1000})
        approval.click()
        page.get_by_text("Nothing is waiting for you.").first.wait_for()


def board_states(browser: Any, origin: str, token: str, expected: set[str]) -> None:
    """Read the live board and insist it says what the run just produced.

    The board maps every execution state to a phase and a word. Nothing in the test suite
    can tell whether that mapping still covers the kernel, because a suite feeding the
    board its own fixtures agrees with itself. A run that actually produced these states,
    reading the page that claims to draw them, is the check that notices when the kernel
    grows a state the picture cannot say.
    """
    words = {
        "DENIED": "denied",
        "PENDING_APPROVAL": "held for a person",
        "EXECUTED": "executed",
        "DISPATCH_COMMITTED": "unsettled",
        "INDETERMINATE": "unsettled",
        "STALE_AUTHORIZATION": "nothing happened",
        "FAILED_NOT_EXECUTED": "nothing happened",
        "OBSERVED": "would have been decided",
    }
    with browser.new_context(base_url=origin, viewport={"width": 1440, "height": 1000}) as context:
        page = context.new_page()
        page.set_default_timeout(15000)
        page.goto("/login?setup=1")
        page.get_by_label("Setup credential").fill(token)
        page.get_by_role("button", name="Continue setup").click()
        page.goto("/board?live=false")
        page.get_by_role("heading", level=1, name="Live board").wait_for()
        # The picture is drawn once the board's own snapshot has answered; the ticker is
        # what carries the words this read is about.
        page.get_by_role("img").first.wait_for()
        body = page.content()
    missing = sorted(state for state in expected if state in words and words[state] not in body)
    if missing:
        raise ValueError(f"The board did not say what the run produced: {missing}")
    unmapped = sorted(state for state in expected if state not in words)
    if unmapped:
        raise ValueError(f"The board has no word for a state this run produced: {unmapped}")


def provider_evidence(private: Path, tenant: str, target: dict[str, Any], expected: int) -> None:
    import sqlite3

    name = "endpoint" if target["provider"] == "mock_crowdstrike" else "identity"
    with sqlite3.connect(private / f"{name}.sqlite3") as conn:
        mutations = conn.execute(
            "SELECT mutation_count FROM resources WHERE tenant_id=? AND canonical_target_id=?",
            (tenant, target["canonical_target_id"]),
        ).fetchone()[0]
        journals = conn.execute(
            "SELECT count(*) FROM journal WHERE tenant_id=? "
            "AND json_extract(command_json,'$.canonical_target_id')=?",
            (tenant, target["canonical_target_id"]),
        ).fetchone()[0]
    if mutations != expected or journals != expected:
        raise ValueError("Unexpected provider mutation or operation journal")


def reconcile_in_browser(browser: Any, origin: str, token: str, execution_id: str) -> None:
    with browser.new_context(base_url=origin) as context:
        page = context.new_page()
        page.set_default_timeout(15000)
        page.goto("/login?setup=1")
        page.get_by_label("Setup credential").fill(token)
        page.get_by_role("button", name="Continue setup").click()
        # The record opens from its own address, and the settlement is a dialog on it (#333).
        page.goto(f"/activity?open={execution_id}")
        drawer = page.get_by_role("dialog")
        drawer.get_by_role("button", name="Reconcile").click()
        dialog = page.get_by_role("dialog", name="Reconcile with provider evidence")
        dialog.get_by_label("Reason", exact=True).fill("Recover controlled demo lost response")
        dialog.get_by_role("button", name="Reconcile with provider evidence").click()
        dialog.wait_for(state="detached")


def exercise(running: DemoServices, output: Path) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    credentials = private_json(running.private / "credentials.json")
    results: list[dict[str, Any]] = []
    with sync_playwright() as playwright, httpx.Client(trust_env=False, timeout=10) as client:
        browser = playwright.chromium.launch()
        browser_version = browser.version
        try:
            for index, tenant in enumerate(running.fixture["tenants"]):
                actors = {actor["label"]: actor for actor in credentials[tenant["tenant_id"]]}
                targets = {target["label"]: target for target in tenant["targets"]}
                token = actors["agent-0"]["token"]
                headers = {"Authorization": "Bearer " + token}
                examples = (
                    ("workstation-01", "endpoint.isolate"),
                    ("workstation-25", "endpoint.isolate"),
                    ("identity-disable", "identity.disable"),
                    ("identity-enable", "identity.enable"),
                    ("identity-revoke-sessions", "identity.revoke_sessions"),
                    ("identity-privileged", "identity.disable"),
                    ("identity-tier0", "identity.disable"),
                )
                for label, action in examples:
                    body = action_request(targets[label], action, "demo-" + label)
                    response = client.post(
                        running.origin + "/v1/execute", json=body, headers=headers
                    )
                    result = response.json()
                    if result.get("state") == "PENDING_APPROVAL":
                        human = (
                            "human_endpoint" if action == "endpoint.isolate" else "human_identity"
                        )
                        browser_approve(
                            browser,
                            running.origin,
                            actors[human]["token"],
                            output,
                            f"tenant-{index}-{label}-approval",
                        )
                        result = client.post(
                            running.origin + "/v1/execute", json=body, headers=headers
                        ).json()
                    expected = (
                        "DENIED"
                        if label in {"identity-privileged", "identity-tier0"}
                        else "EXECUTED"
                    )
                    if result.get("state") != expected:
                        raise ValueError("Unexpected demo execution")
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        retried = pool.submit(
                            asyncio.run, mcp_retry(running.origin, token, body)
                        ).result(timeout=20)
                    if retried["execution"]["execution_id"] != result["execution_id"]:
                        raise ValueError("Retry changed execution identity")
                    provider_evidence(
                        running.private,
                        tenant["tenant_id"],
                        targets[label],
                        0 if expected == "DENIED" else 1,
                    )
                    results.append(
                        {
                            "tenant_id": tenant["tenant_id"],
                            "label": label,
                            "action": action,
                            "state": expected,
                            "execution_id": result["execution_id"],
                            "protocol": retried["protocol"],
                        }
                    )
                # Failure injection belongs only to this trusted local harness.
                target = targets["workstation-02"]
                body = action_request(target, "endpoint.isolate", "demo-lost-response")
                (running.private / "endpoint.drop-response").write_text("drop once after commit")
                uncertain = client.post(
                    running.origin + "/v1/execute", json=body, headers=headers
                ).json()
                if uncertain.get("state") != "INDETERMINATE":
                    raise ValueError("Lost response did not retain uncertainty")
                provider_evidence(running.private, tenant["tenant_id"], target, 1)
                database = Database(os.environ["DATABASE_URL"])
                try:
                    administrator = authenticate(database, actors["admin"]["token"])
                    history = export_history(database, administrator)
                    source = output / f"uncertain-{index}.json"
                    checkpoint = output / f"uncertain-{index}.head.json"
                    publish_export(
                        database, administrator, history, output=source, checkpoint=checkpoint
                    )
                    report = run_replay(source, checkpoint, output / f"uncertain-replay-{index}")
                    if report.decisions[-1].baseline.outcome != "INDETERMINATE":
                        raise ValueError("Replay invented terminal evidence")
                finally:
                    database.close()
                running.stop("endpoint")
                running.start("endpoint")
                reconcile_in_browser(
                    browser, running.origin, actors["admin"]["token"], uncertain["execution_id"]
                )
                recovered = client.post(
                    running.origin + "/v1/execute", json=body, headers=headers
                ).json()
                if (
                    recovered.get("state") != "EXECUTED"
                    or recovered["execution_id"] != uncertain["execution_id"]
                ):
                    raise ValueError("Reconciliation did not recover the exact execution")
                provider_evidence(running.private, tenant["tenant_id"], target, 1)
                results.append(
                    {
                        "tenant_id": tenant["tenant_id"],
                        "label": "lost-response",
                        "action": "endpoint.isolate",
                        "before": "INDETERMINATE",
                        "state": "EXECUTED",
                        "execution_id": recovered["execution_id"],
                        "mutation_count": 1,
                    }
                )
                # The board has to say what this tenant's run produced. Read after the
                # scenarios rather than during them, so it sees every state at once.
                board_states(
                    browser,
                    running.origin,
                    actors["admin"]["token"],
                    {
                        str(row["state"])
                        for row in results
                        if row["tenant_id"] == tenant["tenant_id"]
                    },
                )
            return {"browser_version": browser_version, "executions": results}
        finally:
            browser.close()


def run_demo(
    private: Path, output: Path, listeners: dict[str, socket.socket] | None = None
) -> dict[str, Any]:
    local_database_url(
        os.environ["DATABASE_URL"],
        databases=local_databases(),
        username="execbound_app",
    )
    if output.exists() or output.resolve() == private.resolve():
        raise ValueError("Evidence destination must be new")
    output.mkdir(mode=0o700)
    db = Database(os.environ["DATABASE_URL"])
    try:
        with services(private, listeners) as running:
            evidence = exercise(running, output)
            credentials = private_json(running.private / "credentials.json")
            exports = []
            for index, tenant in enumerate(running.fixture["tenants"]):
                actor = next(a for a in credentials[tenant["tenant_id"]] if a["kind"] == "ADMIN")
                identity = authenticate(db, actor["token"])
                history = export_history(db, identity)
                source, checkpoint = (
                    output / f"tenant-{index}.json",
                    output / f"tenant-{index}.head.json",
                )
                publish_export(db, identity, history, output=source, checkpoint=checkpoint)
                candidate = private_json(running.private / f"candidate-{index}.json")
                write_json(output / f"candidate-{index}.json", candidate)
                exports.append((source, checkpoint, output / f"candidate-{index}.json"))
            for name in ("gateway", "identity", "endpoint"):
                running.stop(name)
            before = (snapshot(db, running.fixture["tenants"]), provider_snapshot(running.private))
            for index, (source, checkpoint, candidate_file) in enumerate(exports):
                baseline = run_replay(source, checkpoint, output / f"baseline-{index}")
                comparison = run_replay(
                    source, checkpoint, output / f"comparison-{index}", candidate_file
                )
                if (
                    not baseline.complete
                    or not baseline.decisions
                    or comparison.mode != "COMPARISON"
                ):
                    raise ValueError("Incomplete demo replay")
                # The same history as a sanitized regression fixture, checked straight away:
                # it must replay to the outcomes it recorded with the providers still stopped.
                fixture = output / f"tenant-{index}.fixture.json"
                run_build(source, checkpoint, (candidate_file,), fixture)
                if run_check(fixture)[1]:
                    raise ValueError("Replay fixture mismatch")
            if before != (
                snapshot(db, running.fixture["tenants"]),
                provider_snapshot(running.private),
            ):
                raise ValueError("Replay changed live state")
            with db.engine.connect() as conn:
                postgres = conn.execute(text("SHOW server_version")).scalar_one()
            evidence.update(
                {
                    "version": 1,
                    "completed_at": datetime.now(UTC).isoformat(),
                    "python": sys.version.split()[0],
                    "postgresql": postgres,
                    "packages": {
                        name: version(name)
                        for name in ("fastapi", "mcp", "playwright", "cedarpy", "sqlalchemy")
                    },
                    "providers_stopped_before_replay": True,
                    "live_fingerprints_unchanged": True,
                    "tenant_count": len(running.fixture["tenants"]),
                    "limitations": [
                        "Controlled mocks only; no real vendor validation.",
                        "SDK compatibility is not a named practitioner-host trial.",
                        "Independent OS sandboxing is not established by this harness.",
                    ],
                }
            )
            write_json(output / "validation.json", evidence)
            return evidence
    finally:
        db.close()


def main() -> None:
    from dotenv import load_dotenv

    parser = argparse.ArgumentParser(description="Trusted loopback validation harness")
    parser.add_argument("command", choices=("serve", "run"))
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    load_dotenv()
    try:
        if args.command == "run":
            if args.output is None:
                parser.error("run requires --output")
            run_demo(args.private, args.output)
            print("Validation complete; allowlisted synthetic evidence created.")
        else:
            with services(args.private) as running:
                print(f"Local demo ready at {running.origin}. Press Ctrl+C to stop.", flush=True)
                while True:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        return
    except HarnessError as failure:
        parser.exit(
            2, f"Validation unavailable: {failure}. Private logs remain in the fixture directory.\n"
        )
    except Exception as failure:
        # Enough to tell a port collision from a real regression, and no more: an
        # arbitrary exception's message can carry fixture values, so it stays unread.
        parser.exit(
            2,
            f"Validation unavailable: {type(failure).__name__} at {_origin(failure)}. "
            "Private logs remain in the fixture directory.\n",
        )


if __name__ == "__main__":
    main()
