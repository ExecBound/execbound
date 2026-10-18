# SPDX-License-Identifier: AGPL-3.0-only
"""A gateway in an operating system process of its own, for tests that need more than one.

`GatewayProcess` runs what the image runs: `execbound.app:create_app` under uvicorn, in a
child Python process configured the way a deployment configures one, with `DATABASE_URL`
naming the runtime role and `EXECBOUND_RUNTIME_CONFIG` the private configuration file. Nothing
is shared with the test process but the database and the files on disk, so a defect that kept
state in a module global would keep it separately in each process, as it would on two hosts.

The process binds its own port, `0` so the kernel picks a free one, before it does anything
else, builds the application, and only then writes the port to `ready` by a rename. The
fixture reads the port from there, for the reason `LiveProvider` in `test_protected_path`
gives: a port reserved here and released for the child to bind is free for the whole of the
child's start, long enough for another xdist worker to take it. Once the port is known the
fixture waits for `GET /health/ready` to answer `ready`, the step the deployment guide asks
an operator to wait for, which checks the schema revision and the runtime role's privileges.

`launch` and `wait` are separate so a test can start several processes before waiting for
any of them; a process that exits before it is ready fails the test with the last lines of
what it wrote.
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from execbound.provider.connector import ConnectionConfig

# The application the image's command builds, `uvicorn execbound.app:create_app --factory`,
# served on a socket this process bound itself, at the image's log settings.
SCRIPT = """
import os, socket
listener = socket.create_server(("127.0.0.1", 0))
import uvicorn
from execbound.app import create_app
app = create_app()
ready = os.environ["TEST_GATEWAY_READY"]
with open(ready + ".tmp", "w") as report:
    report.write(str(listener.getsockname()[1]))
os.replace(ready + ".tmp", ready)
uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="error")).run(sockets=[listener])
"""

# A gateway imports the whole application before it binds, and under a loaded runner that
# takes several seconds; the bound is for a process that will never be ready.
START_SECONDS = 90


def write_configuration(
    path: Path, origin: str, continuation_key: str, connections: list[ConnectionConfig]
) -> Path:
    """A private configuration file holding `connections` as its connectors, at `origin`.

    Every replica of a deployment reads the same file; a test starting several processes
    passes each the path this returns.
    """
    path.write_text(
        json.dumps(
            {
                "origin": origin,
                "active_key_id": "replica-v1",
                "continuation_keys": {"replica-v1": continuation_key},
                "connectors": [
                    {
                        "tenant_id": str(connection.tenant_id),
                        "account_id": str(connection.account_id),
                        "origin": connection.origin,
                        "dispatch_token": connection.dispatch_token,
                        "control_token": connection.control_token,
                        "evidence_keys": {
                            name: key.hex() for name, key in connection.evidence_keys.items()
                        },
                        "timeout_seconds": 10,
                    }
                    for connection in connections
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


@dataclass
class GatewayProcess:
    """One gateway process. `host` is the configured origin's netloc, which a load balancer
    passes through and the gateway refuses any request without."""

    name: str
    database_url: str = field(repr=False)
    configuration: Path
    host: str
    directory: Path
    port: int = 0
    process: subprocess.Popen | None = field(default=None, repr=False)

    @property
    def ready(self) -> Path:
        return self.directory / f"{self.name}.ready"

    @property
    def log(self) -> Path:
        return self.directory / f"{self.name}.log"

    def launch(self) -> None:
        self.ready.unlink(missing_ok=True)
        environment = {
            **os.environ,
            "DATABASE_URL": self.database_url,
            "EXECBOUND_RUNTIME_CONFIG": str(self.configuration),
            "TEST_GATEWAY_READY": str(self.ready),
        }
        # The private file is the whole configuration; an inline copy would replace it.
        environment.pop("EXECBOUND_RUNTIME_CONFIG_JSON", None)
        with self.log.open("ab") as output:
            self.process = subprocess.Popen(
                [sys.executable, "-c", SCRIPT],
                env=environment,
                # Away from the checkout, so no `.env` file there is read in its place.
                cwd=self.directory,
                stdout=output,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

    def _exited(self) -> None:
        assert self.process is not None
        if self.process.poll() is not None:
            last = self.log.read_text(errors="replace").strip().splitlines()[-5:]
            pytest.fail(f"Gateway {self.name} exited before readiness: {last}")

    def wait(self) -> None:
        """Wait for the port report, then for readiness over HTTP."""
        deadline = time.monotonic() + START_SECONDS
        while not self.ready.exists():
            self._exited()
            if time.monotonic() > deadline:
                pytest.fail(f"Gateway {self.name} did not bind a port")
            time.sleep(0.05)
        # The report is written whole, by a rename, only after the process holds the port.
        self.port = int(self.ready.read_text())
        with self.client() as client:
            while True:
                self._exited()
                try:
                    answer = client.get("/health/ready", timeout=5)
                    if answer.status_code == 200 and answer.json()["status"] == "ready":
                        return
                except httpx.TransportError:
                    pass
                if time.monotonic() > deadline:
                    pytest.fail(f"Gateway {self.name} did not become ready")
                time.sleep(0.1)

    def client(self, token: str | None = None) -> httpx.Client:
        """A client of this process alone, sending the origin's `Host` as a balancer would."""
        headers = {"Host": self.host}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        return httpx.Client(
            base_url=f"http://127.0.0.1:{self.port}",
            headers=headers,
            timeout=30,
            follow_redirects=False,
        )

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
