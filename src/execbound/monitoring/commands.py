# SPDX-License-Identifier: AGPL-3.0-only
"""Local monitoring tools. Collection runs only as a command: an operator's `collect-tines` or
`collect-entra`, or the scheduled `collect-due`, which holds no workspace credential. Nothing here
delivers in the background. `collector-keygen` writes the collector's key pair and
`collector-reseal` moves every sealed connection to a new one; the collector's private key is
read only by those and by `collect-due --collector-key`, and the platform app's credential, which
reads every consented directory, only by `collect-due --platform-app`."""

import argparse
import json
import os
import secrets
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TextIO
from uuid import UUID, uuid4

import httpx
import uvicorn
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

from execbound.command_help import describe_common
from execbound.connection import connect_args, local_database_url
from execbound.db import Database, UnsafeDatabaseRole
from execbound.identity import Identity, authenticate, new_token
from execbound.logging_schema import install as install_logging
from execbound.logging_schema import log_event
from execbound.monitoring.collection import fingerprint
from execbound.monitoring.collection import run as collection_run
from execbound.monitoring.delivery import LocalReceiver
from execbound.monitoring.graph import GRAPH_ORIGIN, EntraConfig, PlatformApp
from execbound.monitoring.graph import fingerprint as graph_fingerprint
from execbound.monitoring.graph import run as graph_run
from execbound.monitoring.models import DetectionProfile, MonitorError
from execbound.monitoring.receiver import make_receiver
from execbound.monitoring.store import (
    MAX_CONNECTIONS,
    accept_reach,
    active_profile,
    create_connection,
    create_source,
    link_agent,
    revoke_connection,
    revoke_source,
    rotate_source,
    set_profile,
)
from execbound.monitoring.tines import TinesConfig, check_connection
from execbound.plugins import PluginError, database_refusal, load_command_plugins


class ProfileFileError(ValueError):
    """A profile file was refused; the message names field locations, never values."""


def load_profile_file(path: Path) -> DetectionProfile:
    from pydantic import ValidationError

    if path.stat().st_size > 16384:
        raise ProfileFileError("Profile file is too large")
    try:
        return DetectionProfile.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors(include_input=False, include_url=False)
        )
        raise ProfileFileError(f"Profile file is invalid: {problems}") from None
    except ValueError:
        raise ProfileFileError("Profile file is invalid") from None


class ProvisioningError(ValueError):
    """Static recovery guidance never includes credentials, paths or dependency errors."""

    def __init__(self, code: str) -> None:
        self.code = code
        message = (
            "Source was not provisioned. Correct input/access and retry only if the "
            "output is absent; preserve any "
            "remaining output. The sibling recovery directory records the rejection."
            if code == "NOT_PROVISIONED"
            else "Provisioning may have committed. Preserve the output and sibling "
            ".<output-name>.recovery-* directory. If config-ready.json is complete valid JSON, "
            "use a private copy at a new path. Otherwise inspect the saved phase and "
            "source selectors; "
            "reconcile or revoke the incomplete registration before provisioning again."
        )
        super().__init__(message)


def _private_opener(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


def _flush_json(handle: TextIO, value: dict[str, Any]) -> None:
    json.dump(value, handle, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    with open(str(path), "x", encoding="utf-8", opener=_private_opener) as handle:
        _flush_json(handle, value)


@dataclass
class _Output:
    handle: TextIO
    recovery: Path
    retain: bool = False

    def record(self, name: str, value: dict[str, Any]) -> None:
        # Every phase is a new file: later disk failures cannot erase prior credentials.
        _write_private_json(self.recovery / name, value)


def _remove_owned_empty(output: Path, original: os.stat_result) -> None:
    try:
        current = output.lstat()
        if (
            not output.is_symlink()
            and current.st_size == 0
            and (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)
        ):
            output.unlink()
    except OSError:
        # Never delete another artifact or turn a cleanup failure into false success.
        pass


@contextmanager
def _reserve_output(output: Path) -> Iterator[_Output]:
    output.parent.mkdir(parents=True, exist_ok=True)
    handle = open(str(output), "x", encoding="utf-8", opener=_private_opener)
    original = os.fstat(handle.fileno())
    artifact = None
    try:
        recovery = Path(tempfile.mkdtemp(prefix=f".{output.name}.recovery-", dir=output.parent))
        artifact = _Output(handle, recovery)
        yield artifact
    finally:
        try:
            handle.close()
        except OSError:
            if artifact is not None and artifact.retain:
                raise ProvisioningError("RECOVERY_REQUIRED") from None
            raise
        if artifact is None or not artifact.retain:
            _remove_owned_empty(output, original)


def _issue_source(
    artifact: _Output,
    db: Database,
    identity: Identity,
    *,
    label: str,
    story_id: str,
    expires_at: datetime,
) -> dict[str, Any]:
    metadata = {
        "phase": "SOURCE_PROVISION_PENDING",
        "tenant_id": str(identity.tenant_id),
        "admin_principal_id": str(identity.principal_id),
        "admin_credential_id": str(identity.credential_id),
        "source_id": None,
        "story_id": story_id,
        "label": label,
        "attempted_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    artifact.record("source-pending.json", metadata)
    artifact.retain = True
    grant = create_source(db, identity, label=label, story_id=story_id, expires_at=expires_at)
    artifact.record(
        "source-issued.json",
        metadata
        | {
            "phase": "SOURCE_ISSUED",
            "source_id": str(grant.source_id),
        },
    )
    return {
        "source_id": str(grant.source_id),
        "source_token": grant.token,
        "tenant_id": str(grant.tenant_id),
        "story_id": story_id,
    }


def create_source_file(
    db: Database,
    identity: Identity,
    *,
    label: str,
    story_id: str,
    expires_at: datetime,
    output: Path,
) -> None:
    """Persist recovery evidence and the issued secret before reporting success."""
    with _reserve_output(output) as artifact:
        try:
            config = _issue_source(
                artifact, db, identity, label=label, story_id=story_id, expires_at=expires_at
            )
            artifact.record("config-ready.json", config)
            _flush_json(artifact.handle, config)
        except MonitorError as exc:
            if exc.code in {
                "INVALID_INPUT",
                "INVALID_ADMIN",
                "SOURCE_CAPACITY",
                "SOURCE_EXISTS",
                "INVALID_SPACE",
                "SPACE_ARCHIVED",
            }:
                artifact.retain = False
                try:
                    artifact.record(
                        "not-provisioned.json",
                        {
                            "phase": "NOT_PROVISIONED",
                            "code": exc.code,
                        },
                    )
                except OSError:
                    pass
                raise ProvisioningError("NOT_PROVISIONED") from None
            raise ProvisioningError("RECOVERY_REQUIRED") from None
        except (Exception, KeyboardInterrupt):
            raise ProvisioningError("RECOVERY_REQUIRED") from None


def rotate_source_file(
    db: Database,
    identity: Identity,
    *,
    source_id: UUID,
    expires_at: datetime,
    grace_seconds: int,
    output: Path,
) -> None:
    """Persist recovery evidence and the replacement secret before reporting success."""
    with _reserve_output(output) as artifact:
        try:
            metadata = {
                "phase": "SOURCE_ROTATION_PENDING",
                "tenant_id": str(identity.tenant_id),
                "admin_principal_id": str(identity.principal_id),
                "admin_credential_id": str(identity.credential_id),
                "source_id": str(source_id),
                "attempted_at": datetime.now(UTC).isoformat(),
                "expires_at": expires_at.isoformat(),
                "grace_seconds": grace_seconds,
            }
            artifact.record("source-rotation-pending.json", metadata)
            artifact.retain = True
            grant = rotate_source(
                db, identity, source_id, expires_at=expires_at, grace_seconds=grace_seconds
            )
            artifact.record("source-rotated.json", metadata | {"phase": "SOURCE_ROTATED"})
            config = {
                "source_id": str(grant.source_id),
                "source_token": grant.token,
                "tenant_id": str(grant.tenant_id),
            }
            artifact.record("config-ready.json", config)
            _flush_json(artifact.handle, config)
        except MonitorError as exc:
            if exc.code in {
                "INVALID_INPUT",
                "INVALID_ADMIN",
                "SOURCE_UNAVAILABLE",
                "INVALID_STATE",
            }:
                artifact.retain = False
                try:
                    artifact.record("not-rotated.json", {"phase": "NOT_ROTATED", "code": exc.code})
                except OSError:
                    pass
                raise ProvisioningError("NOT_ROTATED") from None
            raise ProvisioningError("RECOVERY_REQUIRED") from None
        except (Exception, KeyboardInterrupt):
            raise ProvisioningError("RECOVERY_REQUIRED") from None


DEMO_GATEWAY_PORT = 8120
DEMO_RECEIVER_PORT = 8121


def read_private(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 16384:
        raise ValueError("Private configuration unavailable")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Private configuration unavailable")
    return value


def initialize_demo(
    db: Database,
    owner_url: str,
    output: Path,
    *,
    gateway_port: int = DEMO_GATEWAY_PORT,
    receiver_port: int = DEMO_RECEIVER_PORT,
) -> None:
    """Record new ADMIN credentials before any local synthetic provisioning attempt.

    The ports are the demonstration's own loopback listeners. Two runs on one machine
    need different ones, so they are arguments rather than constants."""
    ports = (gateway_port, receiver_port)
    if any(type(port) is not int or not 1024 <= port <= 65535 for port in ports) or (
        gateway_port == receiver_port
    ):
        raise ValueError("Invalid demo ports")
    parsed = local_database_url(owner_url, databases={"execbound"}, username="execbound_owner")
    runtime = local_database_url(
        str(db.engine.url), databases={"execbound"}, username="execbound_app"
    )
    if (parsed.host, parsed.port, parsed.database) != (
        runtime.host,
        runtime.port,
        runtime.database,
    ):
        raise ValueError("Local database mismatch")
    with _reserve_output(output) as artifact:
        tenant, principal, credential = uuid4(), uuid4(), uuid4()
        token, digest = new_token(tenant, credential)
        now = datetime.now(UTC)
        expires_at = now + timedelta(hours=8)
        config = {
            "version": 1,
            "tenant_id": str(tenant),
            "admin_principal_id": str(principal),
            "admin_credential_id": str(credential),
            "admin_token": token,
            "story_id": "lab-story",
            "human_key": secrets.token_hex(32),
            "receiver_secret": secrets.token_urlsafe(32),
            "gateway_port": gateway_port,
            "receiver_port": receiver_port,
            "expires_at": expires_at.isoformat(),
        }
        artifact.record("admin-pending.json", config | {"phase": "ADMIN_PROVISION_PENDING"})
        owner = create_engine(parsed, hide_parameters=True, connect_args=connect_args(parsed))
        try:
            artifact.retain = True
            with owner.begin() as conn:
                conn.execute(
                    text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)}
                )
                conn.execute(
                    text(
                        "INSERT INTO execbound.tenants(tenant_id,name) VALUES (:t,'Monitoring lab')"
                    ),
                    {"t": tenant},
                )
                conn.execute(
                    text(
                        "INSERT INTO execbound.spaces"
                        "(tenant_id,space_id,name,created_at,created_by) "
                        "VALUES (:t,gen_random_uuid(),'Default',now(),:p)"
                    ),
                    {"t": tenant, "p": principal},
                )
                conn.execute(
                    text(
                        "INSERT INTO execbound.principals(tenant_id,principal_id,kind) "
                        "VALUES (:t,:p,'ADMIN')"
                    ),
                    {"t": tenant, "p": principal},
                )
                conn.execute(
                    text("""INSERT INTO execbound.credentials
                    (tenant_id,principal_id,credential_id,token_hash,issued_at,expires_at)
                    VALUES (:t,:p,:c,:h,:n,:e)"""),
                    {
                        "t": tenant,
                        "p": principal,
                        "c": credential,
                        "h": digest,
                        "n": now,
                        "e": expires_at,
                    },
                )
            artifact.record(
                "admin-committed.json",
                {
                    "phase": "ADMIN_COMMITTED",
                    "tenant_id": str(tenant),
                    "admin_principal_id": str(principal),
                    "admin_credential_id": str(credential),
                },
            )
            admin = authenticate(db, token)
            config.update(
                _issue_source(
                    artifact,
                    db,
                    admin,
                    label="Tines security lab",
                    story_id="lab-story",
                    expires_at=expires_at,
                )
            )
            artifact.record("config-ready.json", config)
            _flush_json(artifact.handle, config)
        except (Exception, KeyboardInterrupt):
            raise ProvisioningError("RECOVERY_REQUIRED") from None
        finally:
            owner.dispose()


def build_parser() -> argparse.ArgumentParser:
    """Every monitoring command and its arguments: what `main` parses with, and what
    `scripts/cli_reference.py` writes the command-line reference from."""
    parser = argparse.ArgumentParser(
        description="Explicit Tines monitoring and local validation tools"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-tines", help="Make one read-only Tines stories-list request")
    check.add_argument("--env-file", type=Path, required=True)
    init = sub.add_parser("init-demo", help="Create a new local synthetic monitoring tenant/config")
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--gateway-port", type=int, default=DEMO_GATEWAY_PORT)
    init.add_argument("--receiver-port", type=int, default=DEMO_RECEIVER_PORT)
    source = sub.add_parser("create-source", help="Register one story as a current ADMIN")
    source.add_argument("--credential-file", type=Path, required=True)
    source.add_argument("--label", required=True)
    source.add_argument("--story-id", required=True)
    source.add_argument("--hours", type=int, default=8)
    source.add_argument("--output", type=Path, required=True)
    rotate = sub.add_parser("rotate-source", help="Issue a replacement token as a current ADMIN")
    rotate.add_argument("--credential-file", type=Path, required=True)
    rotate.add_argument("--source", type=UUID, required=True)
    rotate.add_argument("--hours", type=int, default=8)
    rotate.add_argument("--grace-minutes", type=int, default=10)
    rotate.add_argument("--output", type=Path, required=True)
    revoke = sub.add_parser("revoke-source", help="Disable a source for good as a current ADMIN")
    revoke.add_argument("--credential-file", type=Path, required=True)
    revoke.add_argument("--source", type=UUID, required=True)
    connect = sub.add_parser(
        "create-connection", help="Register the read-only collection connection as a current ADMIN"
    )
    connect.add_argument("--credential-file", type=Path, required=True)
    connect.add_argument("--label", required=True)
    connect.add_argument("--key-file", type=Path, required=True)
    connect.add_argument("--kind", choices=("tines", "entra_agent_id"), default="tines")
    connect.add_argument("--team-id")
    connect.add_argument("--space", type=UUID, help="Register in this authorised, active Space")
    disconnect = sub.add_parser(
        "revoke-connection", help="Disable a collection connection as a current ADMIN"
    )
    disconnect.add_argument("--credential-file", type=Path, required=True)
    disconnect.add_argument("--connection", type=UUID, required=True)
    collect = sub.add_parser(
        "collect-tines", help="Run one bounded, read-only collection as a current ADMIN"
    )
    collect.add_argument("--credential-file", type=Path, required=True)
    collect.add_argument("--connection", type=UUID, required=True)
    collect.add_argument("--key-file", type=Path, required=True)
    collect.add_argument("--audit-pages", type=int, default=20)
    collect.add_argument("--inventory", action="store_true")
    collect_entra = sub.add_parser(
        "collect-entra", help="Run one bounded, read-only Entra collection as a current ADMIN"
    )
    collect_entra.add_argument("--credential-file", type=Path, required=True)
    collect_entra.add_argument("--connection", type=UUID, required=True)
    collect_entra.add_argument("--key-file", type=Path, required=True)
    due = sub.add_parser(
        "collect-due",
        help="Collect every due connection this host can open (an operator key file, a sealed "
        "key with --collector-key, a consented directory with --platform-app), inside its lease",
    )
    due.add_argument(
        "--all-tenants",
        action="store_true",
        help="Every active workspace, as its scheduled actor with no credential",
    )
    due.add_argument("--tenant", type=UUID, help="One workspace, as its current ADMIN")
    due.add_argument(
        "--credential-file", type=Path, help="With --tenant: that workspace's ADMIN credential"
    )
    due.add_argument(
        "--key-files",
        type=Path,
        help="A directory of <connection id>.env key files; a connection without one is skipped",
    )
    due.add_argument(
        "--collector-key",
        type=Path,
        action="append",
        help="The collector's private key file, which opens sealed connections; give it again "
        "for the key a rotation is retiring. A path that names no file is no key yet",
    )
    due.add_argument(
        "--platform-app",
        type=Path,
        help="The platform app's credential file, which reads every consented directory. A "
        "path that names no file is no credential yet",
    )
    due.add_argument(
        "--budget-seconds",
        type=int,
        default=240,
        help="Start no collection after this many seconds (1 to 3600, default 240)",
    )
    due.add_argument(
        "--per-tenant",
        type=int,
        default=4,
        help=f"Start at most this many collections a workspace (1 to {MAX_CONNECTIONS}, default 4)",
    )
    keygen = sub.add_parser(
        "collector-keygen",
        help="Write a new collector key pair: the public half for the gateway, the private for "
        "the collector",
    )
    keygen.add_argument(
        "--output",
        type=Path,
        required=True,
        help="A directory for collector-public.json and collector-private.json; neither may exist",
    )
    reseal = sub.add_parser(
        "collector-reseal",
        help="Re-seal every sealed connection from the old collector key to the new one",
    )
    reseal.add_argument(
        "--old-key", type=Path, required=True, help="The current collector's private key file"
    )
    reseal.add_argument(
        "--new-key", type=Path, required=True, help="The new collector's public key file"
    )
    reseal.add_argument(
        "--all-tenants",
        action="store_true",
        help="Every active workspace, as its scheduled actor with no credential",
    )
    for name, help_text in (
        ("link-agent", "Bind an external agent to an active agent principal, as a current ADMIN"),
        ("unlink-agent", "Withdraw that binding, as a current ADMIN"),
    ):
        link = sub.add_parser(name, help=help_text)
        link.add_argument("--credential-file", type=Path, required=True)
        link.add_argument("--connection", type=UUID, required=True)
        link.add_argument("--agent", required=True, help="The directory object identifier")
        if name == "link-agent":
            link.add_argument("--principal", type=UUID, required=True)
    accept = sub.add_parser("accept-reach", help="Record that an ADMIN accepts one ungoverned path")
    accept.add_argument("--credential-file", type=Path, required=True)
    accept.add_argument("--connection", type=UUID, required=True)
    accept.add_argument("--agent", required=True, help="The directory object identifier")
    accept.add_argument("--action", required=True)
    accept.add_argument(
        "--path-kind", required=True, choices=("grant", "role", "inherited", "observation")
    )
    accept.add_argument("--path", required=True)
    accept.add_argument("--reason", required=True, help="A stable reason code, A to Z and _")
    accept.add_argument("--days", type=int, default=0, help="0 leaves the acceptance open")
    set_profile_parser = sub.add_parser(
        "set-profile", help="Activate the next detection profile version as a current ADMIN"
    )
    set_profile_parser.add_argument("--credential-file", type=Path, required=True)
    set_profile_parser.add_argument("--input", type=Path, required=True)
    show_profile_parser = sub.add_parser("show-profile", help="Show the active detection profile")
    show_profile_parser.add_argument("--credential-file", type=Path, required=True)
    for name, description in (
        ("serve", "Serve monitoring with no configured execution connectors"),
        ("receiver", "Run the authenticated loopback test receiver"),
        ("emit-demo", "Send synthetic heartbeat and tool result to the loopback gateway"),
        ("process", "Evaluate a bounded batch; optionally deliver to the local receiver"),
    ):
        command = sub.add_parser(name, help=description)
        # `process` runs either as the configuration's administrator or, for the schedule, in
        # every workspace with no credential; `_check_process` requires exactly one.
        command.add_argument("--config", type=Path, required=name != "process")
        if name == "receiver":
            command.add_argument("--output", type=Path, required=True)
        if name == "process":
            command.add_argument(
                "--all-tenants",
                action="store_true",
                help="Evaluate every active workspace as its scheduled actor; delivers nothing",
            )
            command.add_argument("--deliver-local", action="store_true")
            command.add_argument("--limit", type=int, default=50)
    describe_common(parser)
    return parser


def _check_process(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """What `process` refuses before it reaches the database. `--all-tenants` takes nothing
    another mode reads: it holds no credential and has no receiver, so a configuration's
    administrator token or its local receiver beside it is refused rather than ignored. A
    limit every workspace would refuse is refused once here, rather than by each workspace
    while the run exits 0 having done nothing."""
    if args.all_tenants:
        if args.config is not None or args.deliver_local:
            parser.error("--all-tenants takes no --config or --deliver-local")
        if not 1 <= args.limit <= 50:
            parser.error("--limit must be 1 to 50")
    elif args.config is None:
        parser.error("give --config or --all-tenants")


def _check_collect_due(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """What `collect-due` refuses before it reaches the database: exactly one mode, and bounds
    every workspace would otherwise refuse one by one while the run exits 0."""
    single = args.tenant is not None and args.credential_file is not None
    if args.all_tenants:
        if args.tenant is not None or args.credential_file is not None:
            parser.error("--all-tenants takes no --tenant or --credential-file")
    elif not single:
        parser.error("give --all-tenants or both --tenant and --credential-file")
    if not 1 <= args.per_tenant <= MAX_CONNECTIONS:
        parser.error(f"--per-tenant must be 1 to {MAX_CONNECTIONS}")
    if not 1 <= args.budget_seconds <= 3600:
        parser.error("--budget-seconds must be 1 to 3600")


def _check_reseal(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """`collector-reseal` runs over every workspace, and says so."""
    if not args.all_tenants:
        parser.error("give --all-tenants")


def _http_client() -> httpx.Client:
    """The one client a collection uses: no ambient proxy, no redirect."""
    return httpx.Client(trust_env=False, follow_redirects=False)


def _collect_due(db: Database, args: argparse.Namespace) -> dict[str, Any]:
    """`collect-due` in either mode, logged with counts only."""
    from execbound.monitoring import due, sealing

    # The collector's own keys, read before any workspace is visited: a file that is not one
    # stops the run rather than recording every sealed connection as unopenable. A path that
    # names no file is no key yet, so the schedule can name it before the key is given: each
    # sealed connection is then recorded `COLLECTOR_KEY_UNAVAILABLE`, on the page. During a
    # rotation the key being retired is given beside the new one, and either opens.
    rings = [sealing.read_private_file(path) for path in args.collector_key or () if path.exists()]
    collector = sealing.combine(rings) if rings else None
    # The platform app's credential, read the same way: one that is not one stops the run, and
    # a path that names no file is none yet, so each consented directory records why.
    platform_app = (
        PlatformApp.from_file(args.platform_app)
        if args.platform_app is not None and args.platform_app.exists()
        else None
    )
    with _http_client() as http:
        if args.all_tenants:
            report = due.collect_due(
                db,
                key_files=args.key_files,
                client=http,
                collector=collector,
                platform_app=platform_app,
                per_tenant=args.per_tenant,
                budget_seconds=args.budget_seconds,
            )
            outcomes = list(report["tenants"].values())
            visited, failed = report["visited"], report["failed"]
        else:
            identity = authenticate(db, args.credential_file.read_text(encoding="utf-8").strip())
            if identity.tenant_id != args.tenant or identity.kind != "ADMIN":
                raise MonitorError("INVALID_ADMIN")
            began = time.monotonic()
            report = due.collect_workspace(
                db,
                identity,
                key_files=args.key_files,
                client=http,
                collector=collector,
                platform_app=platform_app,
                per_tenant=args.per_tenant,
                stop=lambda: time.monotonic() - began >= args.budget_seconds,
            )
            outcomes, visited, failed = [report], 1, 0
    log_event(
        "monitor.collect_due",
        count=sum(int(outcome.get("collected", 0)) for outcome in outcomes),
        visited=visited,
        failed=failed,
        not_reached=sum(int(outcome.get("not_reached", 0)) for outcome in outcomes),
        no_key_file=sum(int(outcome.get("no_key_file", 0)) for outcome in outcomes),
        # A delta pass records nothing on its connection, so this line is where one is seen.
        delta=sum(int(outcome.get("delta", 0)) for outcome in outcomes),
        delta_failed=sum(int(outcome.get("delta_failed", 0)) for outcome in outcomes),
        # Nor does an audit-log read that was refused, has not caught up or met the
        # connection's observation bound (#355).
        audit_failed=sum(int(outcome.get("audit_failed", 0)) for outcome in outcomes),
        audit_backlog=sum(int(outcome.get("audit_backlog", 0)) for outcome in outcomes),
        audit_bounded=sum(int(outcome.get("audit_bounded", 0)) for outcome in outcomes),
    )
    return report


def _leased(
    db: Database, identity: Identity, connection: UUID, run: Callable[[UUID], dict[str, Any]]
) -> dict[str, Any]:
    """An operator's collection inside the connection's lease, so it never overlaps the
    schedule's or another operator's."""
    from execbound.monitoring import due

    result = due.claim_and_run(db, identity, connection, run)
    if result is None:
        raise _Busy
    return result


class _Busy(Exception):
    """Another run holds the connection's lease."""


def _process_all(db: Database, limit: int) -> dict[str, Any]:
    """`process --all-tenants`: the scheduled evaluation in every active workspace (#503)."""
    from execbound.jobs import every_workspace
    from execbound.monitoring.worker import evaluate_scheduled

    report = every_workspace(
        db, lambda tenant: evaluate_scheduled(db, tenant, limit=limit), command="process"
    )
    log_event(
        "monitor.process_all",
        count=sum(
            outcome.get("evaluated", 0)
            for outcome in report["tenants"].values()
            if type(outcome.get("evaluated", 0)) is int
        ),
        visited=report["visited"],
        failed=report["failed"],
        not_reached=report["not_reached"],
    )
    return report


def main() -> None:
    install_logging()
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "process":
        _check_process(parser, args)
    if args.command == "collect-due":
        _check_collect_due(parser, args)
    if args.command == "collector-reseal":
        _check_reseal(parser, args)
    try:
        # The plugins EXECBOUND_PLUGINS names, before anything reaches the database, so this
        # process's `check_runtime` expects the dormant grants they claim, as `execbound` does.
        load_command_plugins()
    except PluginError as exc:
        parser.exit(2, f"Plugin refused: {exc.code}.\n")
    try:
        if args.command == "collector-keygen":
            from execbound.monitoring import sealing

            public = sealing.generate(args.output)
            # The key id only: the public half is in its file, and the private half never
            # leaves its own.
            print(json.dumps({"key_id": public.key_id}))
            return
        if args.command == "check-tines":
            with httpx.Client(trust_env=False, follow_redirects=False) as client:
                result = check_connection(TinesConfig.from_file(args.env_file), client)
            print(json.dumps(result))
            return
        if args.command in {"receiver", "emit-demo"}:
            config = read_private(args.config)
            if args.command == "receiver":
                server = make_receiver(
                    config["receiver_port"], config["receiver_secret"], args.output
                )
                try:
                    print("Local receiver ready.", flush=True)
                    server.serve_forever()
                finally:
                    server.server_close()
                return
            port = config["gateway_port"]
            if type(port) is not int or not 1024 <= port <= 65535:
                raise ValueError
            with httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as client:
                for kind in ("heartbeat", "tool_result"):
                    event = {
                        "version": 1,
                        "event_id": str(uuid4()),
                        "story_id": config["story_id"],
                        "occurred_at": datetime.now(UTC).isoformat(),
                        "kind": kind,
                    }
                    if kind == "tool_result":
                        event.update(
                            action="identity.disable", target_ref="lab-user-17", outcome="success"
                        )
                    response = client.post(
                        f"http://127.0.0.1:{port}/v1/monitor/events",
                        json=event,
                        headers={"Authorization": "Bearer " + config["source_token"]},
                    )
                    if response.status_code != 202:
                        raise ValueError
            print("Synthetic heartbeat and reported tool result accepted.")
            return
        load_dotenv()
        db = Database(os.environ["DATABASE_URL"])
        try:
            if args.command == "process" and args.all_tenants:
                print(json.dumps(_process_all(db, args.limit)))
                return
            if args.command == "collector-reseal":
                from execbound.monitoring import due, sealing

                old = sealing.read_private_file(args.old_key)
                new = sealing.read_public_file(args.new_key)
                # Counts only; no key or ciphertext reaches this output.
                report = due.reseal_due(db, old, new)
                log_event(
                    "monitor.collector_resealed",
                    count=report["resealed"],
                    visited=report["visited"],
                    failed=report["failed"],
                )
                print(json.dumps(report))
                return
            if args.command == "collect-due":
                if args.credential_file is not None and args.credential_file.stat().st_size > 1024:
                    raise ValueError
                # Counts only; no key, response content or row value reaches this output.
                print(json.dumps(_collect_due(db, args)))
                return
            if args.command == "init-demo":
                initialize_demo(
                    db,
                    os.environ["MIGRATION_DATABASE_URL"],
                    args.output,
                    gateway_port=args.gateway_port,
                    receiver_port=args.receiver_port,
                )
                print(
                    "Private synthetic monitoring configuration created; no vendor call performed."
                )
                return
            if args.command == "create-source":
                if args.credential_file.stat().st_size > 1024 or not 1 <= args.hours <= 24:
                    raise ValueError
                identity = authenticate(
                    db, args.credential_file.read_text(encoding="utf-8").strip()
                )
                create_source_file(
                    db,
                    identity,
                    label=args.label,
                    story_id=args.story_id,
                    expires_at=datetime.now(UTC) + timedelta(hours=args.hours),
                    output=args.output,
                )
                print("Private source credential created.")
                return
            if args.command in {"set-profile", "show-profile"}:
                if args.credential_file.stat().st_size > 1024:
                    raise ValueError
                identity = authenticate(
                    db, args.credential_file.read_text(encoding="utf-8").strip()
                )
                if args.command == "set-profile":
                    record = set_profile(db, identity, load_profile_file(args.input))
                    print(
                        json.dumps(
                            {"profile_id": str(record.profile_id), "version": record.version}
                        )
                    )
                    return
                current = active_profile(db, identity)
                print(
                    json.dumps(
                        {
                            "profile_id": str(current.profile_id) if current else None,
                            "version": current.version if current else None,
                            "profile": current.profile.model_dump() if current else None,
                        }
                    )
                )
                return
            if args.command == "accept-reach":
                if args.credential_file.stat().st_size > 1024 or not 0 <= args.days <= 365:
                    raise ValueError
                identity = authenticate(
                    db, args.credential_file.read_text(encoding="utf-8").strip()
                )
                accept_reach(
                    db,
                    identity,
                    connection_id=args.connection,
                    platform_ref=args.agent,
                    action=args.action,
                    path_kind=args.path_kind,
                    path_ref=args.path,
                    reason_code=args.reason,
                    expires_at=(
                        datetime.now(UTC) + timedelta(days=args.days) if args.days else None
                    ),
                )
                print("Acceptance recorded; the path is unchanged and still shown.")
                return
            if args.command in {"link-agent", "unlink-agent"}:
                if args.credential_file.stat().st_size > 1024:
                    raise ValueError
                identity = authenticate(
                    db, args.credential_file.read_text(encoding="utf-8").strip()
                )
                link_agent(
                    db,
                    identity,
                    connection_id=args.connection,
                    platform_ref=args.agent,
                    principal_id=args.principal if args.command == "link-agent" else None,
                )
                print(
                    "Agent linked; verified reach can now be derived for it."
                    if args.command == "link-agent"
                    else "Link withdrawn; nothing further is attributed to that principal."
                )
                return
            if args.command in {
                "create-connection",
                "revoke-connection",
                "collect-tines",
                "collect-entra",
            }:
                if args.credential_file.stat().st_size > 1024:
                    raise ValueError
                identity = authenticate(
                    db, args.credential_file.read_text(encoding="utf-8").strip()
                )
                if args.command == "revoke-connection":
                    revoke_connection(db, identity, args.connection)
                    print("Collection connection revoked; no further request is made with it.")
                    return
                entra = args.command == "collect-entra" or (
                    args.command == "create-connection" and args.kind == "entra_agent_id"
                )
                if entra:
                    # The client secret stays in the operator's private file; only its
                    # digest is retained, and the file is read without interpolation.
                    entra_config = EntraConfig.from_file(args.key_file)
                    if args.command == "create-connection":
                        connection_id = create_connection(
                            db,
                            identity,
                            label=args.label,
                            base_url=GRAPH_ORIGIN,
                            key_fingerprint=graph_fingerprint(entra_config.client_secret),
                            kind="entra_agent_id",
                            directory_ref=entra_config.directory_id,
                            client_ref=entra_config.client_id,
                            space=args.space,
                        )
                        print(json.dumps({"connection_id": str(connection_id)}))
                        return
                    with _http_client() as http:
                        secret = entra_config.client_secret
                        result = _leased(
                            db,
                            identity,
                            args.connection,
                            lambda lease: graph_run(
                                db,
                                identity,
                                connection_id=args.connection,
                                client_secret=secret,
                                client=http,
                                lease=lease,
                            ),
                        )
                    # Counts and codes only; no response content ever reaches this output.
                    print(json.dumps(result))
                    return
                # The key stays in the operator's private file; only its digest is retained.
                key_config = TinesConfig.from_file(args.key_file)
                if args.command == "create-connection":
                    connection_id = create_connection(
                        db,
                        identity,
                        label=args.label,
                        base_url=key_config.base_url,
                        key_fingerprint=fingerprint(key_config.api_key),
                        team_id=args.team_id,
                        space=args.space,
                    )
                    print(json.dumps({"connection_id": str(connection_id)}))
                    return
                with _http_client() as http:
                    result = _leased(
                        db,
                        identity,
                        args.connection,
                        lambda lease: collection_run(
                            db,
                            identity,
                            connection_id=args.connection,
                            api_key=key_config.api_key,
                            client=http,
                            inventory=args.inventory,
                            audit_pages=args.audit_pages,
                            lease=lease,
                        ),
                    )
                # Counts and codes only; no response content ever reaches this output.
                print(json.dumps(result))
                return
            if args.command in {"rotate-source", "revoke-source"}:
                if args.credential_file.stat().st_size > 1024:
                    raise ValueError
                identity = authenticate(
                    db, args.credential_file.read_text(encoding="utf-8").strip()
                )
                if args.command == "revoke-source":
                    revoke_source(db, identity, args.source)
                    print("Source revoked; every token it held is refused from now on.")
                    return
                if not 1 <= args.hours <= 24 or not 0 <= args.grace_minutes <= 60:
                    raise ValueError
                rotate_source_file(
                    db,
                    identity,
                    source_id=args.source,
                    expires_at=datetime.now(UTC) + timedelta(hours=args.hours),
                    grace_seconds=args.grace_minutes * 60,
                    output=args.output,
                )
                print("Source credential rotated; the previous token reports until the deadline.")
                return
            config = read_private(args.config)
            identity = authenticate(db, config["admin_token"])
            if args.command == "process":
                from execbound.monitoring.worker import process

                receiver = (
                    LocalReceiver(
                        f"http://127.0.0.1:{config['receiver_port']}/alerts",
                        config["receiver_secret"],
                    )
                    if args.deliver_local
                    else None
                )
                print(json.dumps(process(db, identity, receiver, limit=args.limit)))
            elif args.command == "serve":
                from execbound.app import create_app
                from execbound.runtime import Runtime
                from execbound.surfaces.human import HumanConfig
                from execbound.surfaces.tokens import TokenKeys

                port = config["gateway_port"]
                if type(port) is not int or not 1024 <= port <= 65535:
                    raise ValueError
                human = HumanConfig(
                    f"http://127.0.0.1:{port}",
                    TokenKeys("monitor", {"monitor": bytes.fromhex(config["human_key"])}),
                )
                app = create_app(db, runtime=Runtime(db, []), human=human)
                uvicorn.run(app, host="127.0.0.1", port=port, access_log=False)
        finally:
            db.close()
    except _Busy:
        parser.exit(2, "Collection already running for that connection.\n")
    except ProfileFileError as exc:
        parser.exit(2, str(exc) + "\n")
    except ProvisioningError as exc:
        parser.exit(2, str(exc) + "\n")
    except FileExistsError:
        parser.exit(
            2,
            "Output already exists; no existing credential was overwritten. "
            "Preserve it and inspect any sibling recovery directory before retrying.\n",
        )
    except UnsafeDatabaseRole as exc:
        # The command line's own sentence for each refusal of the runtime check, the grants
        # refusals and any other, so the two say the same about the same database.
        parser.exit(2, database_refusal(exc))
    except (Exception, KeyboardInterrupt):
        # Paths, credentials, response bodies and SQL diagnostics never enter CLI output.
        parser.exit(
            2, "Monitoring command unavailable. Check configuration, access and local services.\n"
        )


if __name__ == "__main__":
    main()
