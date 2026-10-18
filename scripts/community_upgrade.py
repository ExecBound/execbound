# SPDX-License-Identifier: AGPL-3.0-only
"""Upgrade a populated Community installation by the runbook, and prove nothing was lost.

    python3 scripts/community_upgrade.py --old-image execbound:base --new-image execbound:head \\
        --project execbound-upgrade --port 18095 --directory "$RUNNER_TEMP/upgrade"

`docs/INSTALL.md` gives two upgrade commands and a backup that proves it restores. Until this
ran, the only exercise of the upgrade was a trial whose database was already at head, so the
migrations had nothing to do (docs/trials/2026-09-19-community-install.md, step 10). This runs
both sections across a real schema change, on an installation that has governed something:

1. `execbound init` and `execbound quickstart` from the old image: one request executed, one
   denied, exactly as a new installer's first run.
2. The runbook's backup, restored into a second database and verified against the live one.
3. The runbook's upgrade: `EXECBOUND_IMAGE` pointed at the new image, `alembic upgrade head`
   with the owner connection, `docker compose up -d`. The compose file stays the one the old
   `init` wrote, because the runbook does not tell an installer to replace it.
4. The upgraded gateway reports ready, which is the check that the schema is the one it
   expects. The history exported through it holds the pre-upgrade head unchanged at the same
   sequence, so the chain before the upgrade is a prefix of the chain after it.
5. The agent credential issued before the upgrade governs again, with the incidents
   quickstart recorded (read from that export's frozen requests, a format that never
   changes). `ws02.example` is denied again, because the deny rule still wins, and
   `ws01.example` answers `STALE_AUTHORIZATION`, because the provider still holds it
   contained: the provider stores survived the containers being replaced.
6. Every scheduled job completes on the new image, and none fails.
7. The backup is taken and verified again after all of that.

It needs Docker and the standard library only, because the runner runs it with the host's
Python rather than the locked environment. It prints what it established and writes the same
as JSON to `--report`; any step that does not hold stops it with a non-zero exit and says which.
It leaves the installation running, so the workflow can collect logs before taking it down.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# The two endpoints `execbound quickstart` creates (`ENDPOINTS` in src/execbound/quickstart.py),
# by the provider object id its inventory facts carry. tests/test_community_upgrade.py holds the
# two equal.
DEVICES = {"device-ws-01": "ws01.example", "device-ws-02": "ws02.example"}
FIRST_RUN = {"ws01.example": "EXECUTED", "ws02.example": "DENIED"}
AFTER_UPGRADE = {"ws02.example": "DENIED", "ws01.example": "STALE_AUTHORIZATION"}
# The jobs a Community install schedules; `notify` runs only where an approval destination is
# configured (#678), and this install configures none. `audit-verify` completing on the new image
# is the populated install's chain still verifying after the upgrade.
JOBS = ("recover", "monitor-process", "audit-verify")
READY_SECONDS = 90
JOBS_SECONDS = 180


class UpgradeFailed(Exception):
    """A step that did not hold. The message names the step and never a token."""


def rewrite_image(env_text: str, image: str) -> str:
    """The `.env` with `EXECBOUND_IMAGE` pointed at `image`, and nothing else changed."""
    lines = env_text.splitlines(keepends=True)
    found = [i for i, line in enumerate(lines) if line.startswith("EXECBOUND_IMAGE=")]
    if len(found) != 1:
        raise UpgradeFailed(f".env names EXECBOUND_IMAGE {len(found)} times, not once")
    lines[found[0]] = f"EXECBOUND_IMAGE={image}\n"
    return "".join(lines)


def first_decisions(quickstart_output: str) -> dict[str, str]:
    """The hostname and state of each request quickstart reports governing."""
    found = {}
    for match in re.finditer(r"^\s+(\S+\.example)\s+([A-Z_]+)\s+INC-", quickstart_output, re.M):
        found[match.group(1)] = match.group(2)
    return found


def revision(alembic_output: str) -> str:
    """The revision `alembic current` or `alembic heads` names, which must be a single head."""
    heads = re.findall(r"^(\S+) \(head\)$", alembic_output, re.M)
    if len(heads) != 1:
        raise UpgradeFailed(f"expected one alembic head, found {heads or 'none'}")
    return heads[0]


def incidents(export: dict[str, Any]) -> dict[str, str]:
    """The incident each quickstart request claimed, by hostname, from the audit export.

    Each `execution.evaluated` event freezes the request and the facts it was decided on, and
    the frozen form never changes, so this reads a record rather than a table.
    """
    found: dict[str, str] = {}
    for event in export.get("events", []):
        if event.get("kind") != "execution.evaluated":
            continue
        frozen = event.get("payload", {}).get("frozen", {})
        incident = (frozen.get("request", {}).get("claimed_context") or {}).get("incident_id")
        devices = {
            fact.get("source_object_id")
            for fact in frozen.get("facts", [])
            if fact.get("source_kind") == "inventory"
        }
        for device in devices & DEVICES.keys():
            if incident and DEVICES[device] not in found:
                found[DEVICES[device]] = incident
    return found


def history_kept(before: dict[str, Any], export: dict[str, Any]) -> bool:
    """Whether the head verified before the upgrade is still at its sequence after it."""
    for event in export.get("events", []):
        if event.get("sequence") == before["head_sequence"]:
            return bool(event.get("event_hash") == before["head_hash"])
    return False


def job_results(log_text: str) -> tuple[set[str], list[dict[str, Any]]]:
    """Which scheduled jobs completed, and every failure or timeout, from the jobs' logs."""
    completed: set[str] = set()
    failures: list[dict[str, Any]] = []
    for line in log_text.splitlines():
        start = line.find('{"')
        if start < 0:
            continue
        try:
            row = json.loads(line[start:])
        except ValueError:
            continue
        if row.get("event") == "job.completed":
            completed.add(str(row.get("command")))
        elif row.get("event") in {"job.failed", "job.timed_out"}:
            failures.append(row)
    return completed, failures


def verified(report: dict[str, Any], stage: str) -> dict[str, Any]:
    """The one tenant of a restore report, refused unless the restore verified completely."""
    tenants = report.get("tenants", [])
    if not report.get("ok") or len(tenants) != 1:
        raise UpgradeFailed(
            f"the backup {stage} the upgrade did not verify: {report.get('problems')}"
        )
    tenant = tenants[0]
    if not (
        tenant.get("chain_ok")
        and tenant.get("live") == "MATCHES_LIVE"
        and tenant.get("unresolved_executions") == 0
    ):
        raise UpgradeFailed(f"the backup {stage} the upgrade restored incompletely: {tenant}")
    return dict(tenant)


class Installation:
    """One Community installation in a directory, driven by the runbook's own commands."""

    def __init__(self, directory: Path, port: int) -> None:
        self.directory = directory
        self.port = port

    def output(self, *command: str, stdin: bytes | None = None) -> bytes:
        result = subprocess.run(
            command, cwd=self.directory, input=stdin, capture_output=True, check=False
        )
        if result.returncode != 0:
            tail = (result.stdout + result.stderr).decode("utf-8", "replace")[-2000:]
            shown = " ".join(command[:4])
            raise UpgradeFailed(f"`{shown} ...` exited {result.returncode}:\n{tail}")
        return result.stdout

    def run(self, *command: str, stdin: bytes | None = None) -> str:
        return self.output(*command, stdin=stdin).decode("utf-8", "replace")

    def compose(self, *arguments: str, stdin: bytes | None = None) -> str:
        return self.run("docker", "compose", *arguments, stdin=stdin)

    def owner_db(self, *command: str, stdin: bytes | None = None) -> bytes:
        password = self.env("POSTGRES_PASSWORD")
        return self.output(
            "docker",
            "compose",
            "exec",
            "-T",
            "-e",
            f"PGPASSWORD={password}",
            "db",
            *command,
            stdin=stdin,
        )

    def env(self, name: str) -> str:
        for line in (self.directory / ".env").read_text().splitlines():
            if line.startswith(f"{name}="):
                return line.split("=", 1)[1]
        raise UpgradeFailed(f".env names no {name}")

    def backup_and_verify(self, stage: str) -> dict[str, Any]:
        """The runbook's backup, restored into a second database and verified against live."""
        raw = self.owner_db("pg_dump", "-Fc", "-U", "execbound_owner", "execbound")
        (self.directory / "backups").mkdir(exist_ok=True)
        (self.directory / "backups" / f"{stage}.dump").write_bytes(raw)
        self.owner_db("createdb", "-U", "execbound_owner", "execbound_restore")
        try:
            self.owner_db(
                "pg_restore", "-U", "execbound_owner", "-d", "execbound_restore", stdin=raw
            )
            reports = self.directory / "reports"
            reports.mkdir(exist_ok=True)
            self.compose(
                "run",
                "--rm",
                "-v",
                f"{reports}:/out",
                "gateway",
                "python",
                "-m",
                "execbound.recovery",
                "--restored-database",
                "execbound_restore",
                "--compare-live",
                "--output",
                f"/out/{stage}.json",
            )
        finally:
            self.owner_db("dropdb", "-U", "execbound_owner", "execbound_restore")
        report = json.loads((self.directory / "reports" / f"{stage}.json").read_text())
        return verified(report, stage)

    def wait_ready(self) -> None:
        url = f"http://127.0.0.1:{self.port}/health/ready"
        deadline = time.monotonic() + READY_SECONDS
        last = "no answer"
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=5) as response:  # nosec B310 - loopback
                    if response.status == 200:
                        return
                    last = f"HTTP {response.status}"
            except urllib.error.HTTPError as error:
                last = f"HTTP {error.code}"
            except OSError as error:
                last = type(error).__name__
            time.sleep(1)
        raise UpgradeFailed(
            f"the upgraded gateway did not become ready in {READY_SECONDS}s ({last})"
        )

    def execute(self, hostname: str, incident: str, reference: str) -> str:
        token = (self.directory / "state" / "agent.token").read_text().strip()
        body = json.dumps(
            {
                "operation_ref": "endpoint.isolate",
                "target": {"kind": "hostname", "value": hostname},
                "arguments": {},
                "reference": reference,
                "claimed_context": {"incident_id": incident},
            }
        ).encode()
        request = urllib.request.Request(  # nosec B310 - loopback
            f"http://127.0.0.1:{self.port}/v1/execute",
            data=body,
            headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 - loopback
                answer = json.loads(response.read())
        except urllib.error.HTTPError as error:
            raise UpgradeFailed(
                f"{hostname} after the upgrade: HTTP {error.code} {error.read()[:200]!r}"
            ) from None
        return str(answer.get("state"))

    def wait_for_jobs(self) -> set[str]:
        deadline = time.monotonic() + JOBS_SECONDS
        completed: set[str] = set()
        while time.monotonic() < deadline:
            completed, failures = job_results(self.compose("logs", "jobs"))
            if failures:
                raise UpgradeFailed(f"a scheduled job failed on the new image: {failures}")
            if set(JOBS) <= completed:
                return completed
            time.sleep(3)
        raise UpgradeFailed(f"never completed on the new image: {sorted(set(JOBS) - completed)}")


def upgrade(
    old_image: str, new_image: str, project: str, port: int, directory: Path, say: Any = print
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=False)
    install = Installation(directory, port)
    install.run(
        "docker",
        "run",
        "--rm",
        "-u",
        f"{os.getuid()}:{os.getgid()}",
        "-v",
        f"{directory}:/install",
        old_image,
        "execbound",
        "init",
        "/install",
        "--project",
        project,
        "--image",
        old_image,
        "--port",
        str(port),
    )
    install.compose("up", "-d")
    first = first_decisions(install.compose("run", "--rm", "gateway", "execbound", "quickstart"))
    if first != FIRST_RUN:
        raise UpgradeFailed(f"quickstart on the old image governed {first}, not {FIRST_RUN}")
    before_revision = revision(install.compose("run", "--rm", "gateway", "alembic", "current"))
    say(f"Installed {old_image} at {before_revision}: {first}.")
    before = install.backup_and_verify("before")
    say(f"Backup before the upgrade verified: {before['events']} events, chain intact.")

    env = directory / ".env"
    env.write_text(rewrite_image(env.read_text(), new_image))
    install.compose("run", "--rm", "gateway", "alembic", "upgrade", "head")
    after_revision = revision(install.compose("run", "--rm", "gateway", "alembic", "current"))
    target = revision(install.run("docker", "run", "--rm", new_image, "alembic", "heads"))
    if after_revision != target:
        raise UpgradeFailed(f"upgraded to {after_revision}, but {new_image} expects {target}")
    install.compose("up", "-d")
    install.wait_ready()
    say(f"Upgraded {before_revision} -> {after_revision} and the gateway is ready.")

    tenant = before["tenant_id"]
    reports = directory / "reports"
    install.compose(
        "run",
        "--rm",
        "-v",
        f"{reports}:/out",
        "gateway",
        "execbound",
        "audit-export",
        "--tenant",
        tenant,
        "--credential-file",
        "/srv/state/admin.token",
        "--output",
        "/out/export.json",
    )
    export = json.loads((reports / "export.json").read_text())
    if not history_kept(before, export):
        raise UpgradeFailed("the chain after the upgrade does not hold the pre-upgrade head")
    claimed = incidents(export)
    if sorted(claimed) != sorted(FIRST_RUN):
        raise UpgradeFailed(f"the export records incidents for {sorted(claimed)}")
    decided = {
        hostname: install.execute(hostname, claimed[hostname], f"UPGRADE-{i}")
        for i, hostname in enumerate(AFTER_UPGRADE, 1)
    }
    if decided != AFTER_UPGRADE:
        raise UpgradeFailed(f"after the upgrade the gateway decided {decided}, not {AFTER_UPGRADE}")
    say(f"The pre-upgrade agent governs again: {decided}.")

    jobs = install.wait_for_jobs()
    say(f"Every scheduled job completed on the new image: {sorted(jobs)}.")
    after = install.backup_and_verify("after")
    if after["events"] < before["events"] + len(AFTER_UPGRADE):
        raise UpgradeFailed(
            f"{after['events']} events after the upgrade, {before['events']} before"
        )
    say(f"Backup after the upgrade verified: {after['events']} events, chain intact.")
    return {
        "old_image": old_image,
        "new_image": new_image,
        "revision_before": before_revision,
        "revision_after": after_revision,
        "migrated": before_revision != after_revision,
        "first_run": first,
        "after_upgrade": decided,
        "events_before": before["events"],
        "events_after": after["events"],
        "head_before": before["head_hash"],
        "jobs": sorted(jobs),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--old-image", required=True)
    parser.add_argument("--new-image", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--directory", type=Path, required=True, help="must not exist yet")
    parser.add_argument("--report", type=Path, help="write what was established as JSON")
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        result = upgrade(args.old_image, args.new_image, args.project, args.port, args.directory)
    except UpgradeFailed as failure:
        print(f"Upgrade check failed: {failure}", file=sys.stderr)
        return 1
    result["seconds"] = round(time.monotonic() - started)
    if args.report:
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        f"Upgraded a populated installation {result['revision_before']} -> "
        f"{result['revision_after']} with its history, credentials and provider state intact "
        f"({result['seconds']}s)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
