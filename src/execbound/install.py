# SPDX-License-Identifier: AGPL-3.0-only
"""Write a complete one-host installation into a directory, from nothing but the image.

`execbound init <dir>` is the first of the three commands an installer runs. It reaches no
database and no network: it copies the compose file, the role script and the starter ruleset
out of the wheel, generates two passwords and the private material the processes read, and
writes a `.env` naming the uid and gid it ran as. `execbound quickstart` then makes the
database agree with what this wrote.

The identifiers are generated here, not discovered later. The private configuration names one
tenant and both connector accounts, and quickstart creates rows carrying exactly those ids, so
the gateway can start before the tenant exists rather than needing a restart afterwards. They
are identifiers rather than secrets; the file that holds them also holds every token the
deployment has, which is why it is written 0600 and never printed.
"""

from __future__ import annotations

import os
import secrets
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, TextIO
from uuid import UUID, uuid4

from execbound.bootstrap import MOCK_PRECONDITIONS, provider_material, write_private

DEFAULT_IMAGE = "execbound:community"
DEFAULT_PORT = 8080
DEFAULT_PROJECT = "execbound"
# The two mock providers, on the loopback addresses the shared network namespace makes real.
ENDPOINT_ORIGIN = "http://127.0.0.1:8001"
IDENTITY_ORIGIN = "http://127.0.0.1:8002"
# Copied out of the wheel verbatim. One copy of each file exists, in the package, because a
# second copy in the repository is a copy that drifts.
BUNDLE_FILES = ("compose.yaml", "starter-rules.json")
INITDB_SCRIPT = "01-runtime-role.sh"
# Each directory and the mode it is created with. The two that hold credentials are the
# installer's alone; `initdb/` is read by PostgreSQL's own entrypoint, which runs as the
# database image's user and cannot open a directory nobody but the installer may read —
# found by installing, where the database container simply reported itself unhealthy.
# `collector/` holds the monitoring collector's key pair, which `collector-keygen` writes there;
# only the jobs container mounts it, because the gateway must never hold a key that opens a
# sealed monitoring key.
DIRECTORIES = (
    ("private", 0o700),
    ("state", 0o700),
    ("providers", 0o700),
    ("collector", 0o700),
    ("initdb", 0o755),
)


class InstallError(Exception):
    """A refusal the installer is shown. It names a path, never a generated value."""


@dataclass(frozen=True)
class Installation:
    """What `init` wrote, for the command to report and the tests to read."""

    directory: Path
    tenant_id: UUID
    endpoint_account_id: UUID
    identity_account_id: UUID
    telemetry: bool
    port: int


def _bundle() -> Any:
    return resources.files("execbound.data").joinpath("community")


def targets(directory: Path) -> tuple[Path, ...]:
    """Every path `install` writes, in the order it writes them."""
    return (
        directory / "compose.yaml",
        directory / "starter-rules.json",
        directory / "initdb" / INITDB_SCRIPT,
        directory / ".env",
        directory / "private" / "gateway.json",
        directory / "private" / "endpoint-accounts.json",
        directory / "private" / "identity-accounts.json",
    )


def ask_telemetry(answer: bool | None, *, input_stream: TextIO, output: TextIO) -> bool:
    """One question, asked once, answered no by default and by silence.

    `docker run` without a terminal has no one to ask, and an installer who is not there has
    not opted in to anything. The prompt is skipped and the answer is no, which is the same
    answer an empty line gives.
    """
    if answer is not None:
        return answer
    if not input_stream.isatty():
        return False
    output.write(
        "Record whether this deployment may send ExecBound a weekly usage report once that "
        "exists (a random install id, the version and counts in rough buckets; never a name, "
        "target, identity, policy or decision)? Nothing is sent today. [y/N] "
    )
    output.flush()
    try:
        reply = input_stream.readline()
    except (EOFError, OSError):
        return False
    return reply.strip().lower() in {"y", "yes"}


def _write(path: Path, contents: str, *, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(contents)


def environment_file(
    values: Mapping[str, str | int],
) -> str:
    """The `.env` beside the compose file: every variable it interpolates, with a comment."""
    lines = [
        "# ExecBound, written by `execbound init`. Private: it holds this deployment's two",
        "# database passwords. Nothing here is committed and nothing here is printed.",
        "#",
        "# Both passwords are read only when the database volume is first created. Changing",
        "# one afterwards does not change the role, and the gateway then fails to connect",
        "# with a value the database does not expect. To start genuinely fresh, take the",
        "# volume with it: `docker compose down -v`.",
        "",
        "# The schema owner. Migrations and administrative commands connect as this role.",
        f"POSTGRES_PASSWORD={values['POSTGRES_PASSWORD']}",
        "",
        "# The restricted runtime role the gateway connects as. It owns no tables and cannot",
        "# bypass row-level security, which readiness checks.",
        f"EXECBOUND_APP_PASSWORD={values['EXECBOUND_APP_PASSWORD']}",
        "",
        "# Names this installation, and its database volume with it. Two installations",
        "# sharing a name share a database.",
        f"EXECBOUND_PROJECT={values['EXECBOUND_PROJECT']}",
        "",
        "# The image to run. When a registry publishes one, this becomes a pull reference",
        "# and nothing else in the installation changes.",
        f"EXECBOUND_IMAGE={values['EXECBOUND_IMAGE']}",
        "",
        "# Where the gateway listens on this host. Loopback only; put a TLS terminator in",
        "# front of it before anyone else reaches it, and change `origin` in",
        "# private/gateway.json to the origin they will use.",
        f"EXECBOUND_PORT={values['EXECBOUND_PORT']}",
        "",
        "# The containers run as you, so they can read the private material you own and you",
        "# can read the credential files they write. `execbound init` wrote the uid and gid",
        "# it ran as, which is why it runs as you.",
        f"EXECBOUND_UID={values['EXECBOUND_UID']}",
        f"EXECBOUND_GID={values['EXECBOUND_GID']}",
        "",
        "# The private material, mounted read-only; the provider journals an uncertain",
        "# operation settles from; and the credential files quickstart issues. Back the",
        "# second one up with the database.",
        "EXECBOUND_PRIVATE=./private",
        "EXECBOUND_PROVIDERS=./providers",
        "EXECBOUND_STATE=./state",
        "",
        "# The monitoring collector's key pair, mounted into the jobs container alone. Empty",
        "# until you run collector-keygen; see docs/INSTALL.md.",
        "EXECBOUND_COLLECTOR=./collector",
        "",
        "# Resources the mock providers hold at start, as a JSON list. Quickstart provisions",
        "# its own two directly into the endpoint store, so this stays empty unless you add",
        "# targets of your own; see docs/INSTALL.md.",
        "EXECBOUND_ENDPOINT_RESOURCES=[]",
        "EXECBOUND_IDENTITY_RESOURCES=[]",
        "",
    ]
    return "\n".join(lines)


def install(
    directory: Path,
    *,
    image: str = DEFAULT_IMAGE,
    port: int = DEFAULT_PORT,
    project: str = DEFAULT_PROJECT,
    telemetry: bool = False,
    origin: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
) -> Installation:
    """Write the whole installation, refusing a directory that already holds one.

    Everything is checked before anything is written: a half-written installation whose
    passwords are in the `.env` and whose private configuration is missing would fail several
    commands later, with the database volume already created from the password it holds.
    """
    if not 1024 <= port <= 65535:
        raise InstallError("The gateway port must be between 1024 and 65535")
    if not project or not project.replace("-", "").replace("_", "").isalnum():
        raise InstallError("The project name must be letters, digits, - or _")
    if not image or any(character.isspace() for character in image):
        raise InstallError("The image reference must be one word")
    existing = [path for path in targets(directory) if path.exists()]
    if existing:
        raise InstallError(
            f"{directory} already holds an installation ({existing[0].name}); "
            "choose an empty directory or remove it deliberately"
        )
    try:
        directory.mkdir(parents=True, exist_ok=True)
        for name, mode in DIRECTORIES:
            made = directory / name
            made.mkdir(mode=mode, exist_ok=True)
            # `mkdir` takes the process umask off the mode it was given, and the image sets
            # a restrictive one, so the mode is set again explicitly.
            made.chmod(mode)
    except OSError as error:
        raise InstallError(f"{directory} could not be created or written") from error

    tenant, endpoint_account, identity_account = uuid4(), uuid4(), uuid4()
    connectors = []
    accounts = {}
    for provider, account, provider_origin, key_id, file in (
        ("mock_crowdstrike", endpoint_account, ENDPOINT_ORIGIN, "endpoint-journal-v1", "endpoint"),
        ("mock_entra", identity_account, IDENTITY_ORIGIN, "identity-journal-v1", "identity"),
    ):
        connector, record = provider_material(
            provider, tenant, str(account), provider_origin, key_id=key_id
        )
        connectors.append(connector)
        accounts[f"{file}-accounts.json"] = [record]
    configuration = {
        "origin": origin or f"http://127.0.0.1:{port}",
        "active_key_id": "continuation-v1",
        "continuation_keys": {"continuation-v1": secrets.token_hex(32)},
        "connectors": connectors,
        "preconditions": [
            {
                "provider": provider,
                "provider_operation": operation,
                "precondition_class": "ENFORCED_BY_PROVIDER",
            }
            for provider, operation in MOCK_PRECONDITIONS
        ],
        # Recorded, and nothing more: no report is composed, sent or scheduled anywhere in
        # this deployment. The setting is what an operator turns on later (#411).
        "telemetry": {"enabled": telemetry},
    }
    passwords = {
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "EXECBOUND_APP_PASSWORD": secrets.token_urlsafe(32),
    }
    bundle = _bundle()
    try:
        for name in BUNDLE_FILES:
            shutil.copyfile(str(bundle.joinpath(name)), directory / name)
        script = directory / "initdb" / INITDB_SCRIPT
        shutil.copyfile(str(bundle.joinpath("initdb").joinpath(INITDB_SCRIPT)), script)
        script.chmod(0o755)
        _write(
            directory / ".env",
            environment_file(
                {
                    **passwords,
                    "EXECBOUND_PROJECT": project,
                    "EXECBOUND_IMAGE": image,
                    "EXECBOUND_PORT": port,
                    "EXECBOUND_UID": os.getuid() if uid is None else uid,
                    "EXECBOUND_GID": os.getgid() if gid is None else gid,
                }
            ),
            mode=0o600,
        )
        write_private(directory / "private", "gateway.json", configuration)
        for name, record_list in accounts.items():
            write_private(directory / "private", name, record_list)
    except (OSError, FileExistsError) as error:
        raise InstallError(f"{directory} could not be written completely") from error
    return Installation(
        directory=directory,
        tenant_id=tenant,
        endpoint_account_id=endpoint_account,
        identity_account_id=identity_account,
        telemetry=telemetry,
        port=port,
    )


def report(result: Installation, *, output: TextIO = sys.stdout) -> None:
    """The path and what happens next. Never a password, a token or a key."""
    output.write(
        f"Installation written to {result.directory}.\n"
        f"Telemetry is {'on' if result.telemetry else 'off'}; "
        "the setting is in private/gateway.json, and nothing sends a report yet.\n"
        "Next:\n"
        f"  cd {result.directory}\n"
        "  docker compose up -d\n"
        "  docker compose run --rm gateway execbound quickstart\n"
    )
