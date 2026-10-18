# SPDX-License-Identifier: AGPL-3.0-only
"""Start a container process from private material handed over as environment variables.

Some hosts (Render blueprints among them) cannot mount secret files, so the gateway's
runtime configuration, a mock provider's accounts file, a scheduled job's ADMIN token or
tenant-to-token map, the monitoring collector's operator key files, its private key and the
platform app's credential, and the database CA bundle arrive as environment variables. The mail
relay's password may arrive on its own (`EXECBOUND_MAIL_PASSWORD`), so the person who owns
the mailbox can set it without handling the rest of the configuration; it is merged into the
configuration's `mail` block, and only there. This
module writes each of them to an owner-only file, provisions a mock provider's store when a
resources list is supplied, removes the values from the environment, and replaces itself
with the real process. A caller may add its own boot files through the `files` hook, writing
after core's own and scrubbing its own variables through `consumed`:

    python -m execbound.boot uvicorn execbound.app:create_app --factory --host 0.0.0.0 --port 8000

No shell is involved, so the start command needs no quoting. A `$NAME` in an argument is
expanded from the environment before the exec and must be set. Nothing here reads the
database or the network, and no value is ever printed.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

from execbound.assistant.config import KEY_VARIABLE as ASSISTANT_KEY_VARIABLE

DEFAULT_DIRECTORY = "/tmp/execbound"  # nosec B108 - the image's only writable path; files are owner-only
MAX_MATERIAL_BYTES = 1024 * 1024
MAX_RESOURCES = 10_000
MAX_TOKEN_BYTES = 160
CA_FILE = "supabase-ca.crt"
TOKEN_FILE = "admin.token"  # nosec B105 - a file name, not a secret
MONITOR_FILE = "monitor.json"
JOBS_FILE = "jobs.json"
MAX_JOB_TENANTS = 64
# The monitoring collector's operator key files (#678): one `<connection id>.env` each, where
# `collect-due --key-files` reads them. A key file is what the operator's own
# `collect-tines --key-file` reads, so it is bounded as that reader bounds it.
KEY_FILES = "key-files"
MAX_KEY_FILES = 1000
MAX_KEY_FILE_BYTES = 16384
# The monitoring collector's private key (#678), which opens every key the console sealed:
# written where `collect-due --collector-key` reads it, and only on the service whose group
# carries it. During a rotation the group also carries the key being retired, written beside it.
COLLECTOR_KEY_FILE = "collector-private.json"
COLLECTOR_PREVIOUS_KEY_FILE = "collector-previous.json"
COLLECTOR_KEY_VARIABLES = {
    "EXECBOUND_COLLECTOR_KEY_JSON": COLLECTOR_KEY_FILE,
    "EXECBOUND_COLLECTOR_PREVIOUS_KEY_JSON": COLLECTOR_PREVIOUS_KEY_FILE,
}
# The platform app's credential (#678), whose certificate reads every directory that consented
# to the deployment's app: written where `collect-due --platform-app` reads it, and only on the
# service whose group carries it.
SCOUT_APP_FILE = "scout-app.json"
# Each sign-in provider's OAuth client secret, handed over the way the mail password and the
# assistant key are: one variable, never written into the file beside the client id.
SIGN_IN_SECRET_VARIABLES = {
    "google": "EXECBOUND_GOOGLE_CLIENT_SECRET",  # nosec B105 - a variable name
    "github": "EXECBOUND_GITHUB_CLIENT_SECRET",  # nosec B105 - a variable name
    "microsoft": "EXECBOUND_MICROSOFT_CLIENT_SECRET",  # nosec B105 - a variable name
}
PROVIDERS = {"mock_crowdstrike", "mock_entra"}
RESOURCE_KEYS = frozenset(
    {"tenant_id", "account_id", "provider_id", "canonical_target_id", "version"}
)
RESOURCE_FLAGS = frozenset({"contained", "account_enabled"})
CONSUMED = (
    "SUPABASE_CA_B64",
    "EXECBOUND_RUNTIME_CONFIG_JSON",
    "EXECBOUND_MOCK_ACCOUNTS_JSON",
    "EXECBOUND_MOCK_RESOURCES_JSON",
    "EXECBOUND_ADMIN_TOKEN",
    "EXECBOUND_JOBS_TOKENS_JSON",
    "EXECBOUND_COLLECTOR_KEY_FILES_JSON",
    "EXECBOUND_COLLECTOR_KEY_JSON",
    "EXECBOUND_COLLECTOR_PREVIOUS_KEY_JSON",
    "EXECBOUND_SCOUT_APP_JSON",
    "EXECBOUND_MAIL_PASSWORD",
    "EXECBOUND_MFA_KEYS_JSON",
    "EXECBOUND_ASSISTANT_API_KEY",
    "EXECBOUND_GOOGLE_CLIENT_SECRET",
    "EXECBOUND_GITHUB_CLIENT_SECRET",
    "EXECBOUND_MICROSOFT_CLIENT_SECRET",
)
# Removed before the exec without being written anywhere: a value the started process must
# not hold. The Community compose file gives the gateway's container the schema owner's URL
# so that a one-off `docker compose run` can apply migrations and administer the deployment,
# and the long-running gateway, which is the process facing the network, is started through
# this module precisely so that it never sees it.
WITHHELD = ("MIGRATION_DATABASE_URL",)
# What `MailConfig` admits: printable ASCII, so an app password's spaces survive.
_MAIL_PASSWORD = re.compile(r"[\x20-\x7e]{1,512}")
_VARIABLE = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})")

# A caller's own boot files. Called with the environment, the boot directory and the runtime
# configuration document before anything is written, so a bad input refuses first; the
# pairs it returns are written after core's own files.
BootFiles = Callable[[Mapping[str, str], Path, bytes | None], list[tuple[Path, bytes]]]


class BootError(Exception):
    """A refusal; the message names a variable, never its value."""


def _write(path: Path, data: bytes) -> None:
    if len(data) > MAX_MATERIAL_BYTES:
        raise BootError(f"{path.name} exceeds {MAX_MATERIAL_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _is_token(value: object) -> bool:
    return (
        type(value) is str
        and value.isascii()
        and not any(character.isspace() for character in value)
        and 0 < len(value) <= MAX_TOKEN_BYTES
    )


def _json_document(environment: MutableMapping[str, str], name: str) -> bytes | None:
    raw = environment.get(name)
    if not raw:
        return None
    try:
        json.loads(raw)
    except ValueError:
        raise BootError(f"{name} is not JSON") from None
    return raw.encode("utf-8")


class _Duplicate(ValueError):
    pass


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _Duplicate
    return dict(pairs)


def _runtime_config(environment: MutableMapping[str, str]) -> bytes | None:
    """The runtime configuration, with the mail password and the assistant key merged in
    when each arrives alone.

    Without a `mail` block the bytes are written as supplied and a set password changes
    nothing, so the variable can be set before the block is added. A block that ends up with
    no password, or with one in both places, refuses to start with a message that names the
    variable and never the value.
    """
    raw = environment.get("EXECBOUND_RUNTIME_CONFIG_JSON")
    if not raw:
        return None
    password = environment.get("EXECBOUND_MAIL_PASSWORD") or None
    try:
        document = json.loads(raw, object_pairs_hook=_unique)
    except _Duplicate:
        raise BootError("EXECBOUND_RUNTIME_CONFIG_JSON has a duplicate key") from None
    except ValueError:
        raise BootError("EXECBOUND_RUNTIME_CONFIG_JSON is not JSON") from None
    changed = False
    mfa_raw = environment.get("EXECBOUND_MFA_KEYS_JSON")
    if mfa_raw:
        from execbound.envelope import KeyRing

        try:
            if not isinstance(document, dict) or document.get("mfa") is not None:
                raise ValueError
            mfa = json.loads(mfa_raw, object_pairs_hook=_unique)
            if not isinstance(mfa, dict) or set(mfa) != {"active_key_id", "keys"}:
                raise ValueError
            if not isinstance(mfa["keys"], dict) or len(mfa["keys"]) > 8:
                raise ValueError
            KeyRing(
                mfa["active_key_id"],
                {name: bytes.fromhex(value) for name, value in mfa["keys"].items()},
            )
        except (ValueError, TypeError, AttributeError):
            raise BootError(
                "EXECBOUND_MFA_KEYS_JSON is invalid or duplicates the mfa block"
            ) from None
        document["mfa"] = mfa
        changed = True
    mail = document.get("mail") if isinstance(document, dict) else None
    if mail is not None:
        if not isinstance(mail, dict):
            raise BootError("the mail block is not an object")
        if "password" in mail:
            if password is not None:
                raise BootError(
                    "EXECBOUND_MAIL_PASSWORD and a password in the mail block; keep one"
                )
        else:
            if password is None:
                raise BootError("the mail block has no password; set EXECBOUND_MAIL_PASSWORD")
            if not _MAIL_PASSWORD.fullmatch(password):
                raise BootError("EXECBOUND_MAIL_PASSWORD is not a password")
            mail["password"] = password
            changed = True
    # The assistant's key, by the same rule: in the environment or in the block, never both,
    # and a block without one refuses to start with the variable's name and never a value.
    assistant = document.get("assistant") if isinstance(document, dict) else None
    key = environment.get(ASSISTANT_KEY_VARIABLE) or None
    if assistant is not None:
        if not isinstance(assistant, dict):
            raise BootError("the assistant block is not an object")
        if "api_key" in assistant:
            if key is not None:
                raise BootError(
                    f"{ASSISTANT_KEY_VARIABLE} and an api_key in the assistant block; keep one"
                )
        else:
            if key is None:
                raise BootError(f"the assistant block has no api_key; set {ASSISTANT_KEY_VARIABLE}")
            if not _MAIL_PASSWORD.fullmatch(key):
                raise BootError(f"{ASSISTANT_KEY_VARIABLE} is not a key")
            assistant["api_key"] = key
            changed = True
    # Each provider's client secret, by the same rule again: the person who owns the OAuth
    # client sets one variable and never edits the file, and a block with the secret in both
    # places refuses to start rather than leaving two answers to which one is current.
    sign_in = document.get("sign_in") if isinstance(document, dict) else None
    for provider, variable in SIGN_IN_SECRET_VARIABLES.items():
        block = sign_in.get(provider) if isinstance(sign_in, dict) else None
        client_secret = environment.get(variable) or None
        if block is None:
            continue
        if not isinstance(block, dict):
            raise BootError(f"the {provider} block is not an object")
        if "client_secret" in block:
            if client_secret is not None:
                raise BootError(f"{variable} and a client_secret in the {provider} block; keep one")
            continue
        if client_secret is None:
            raise BootError(f"the {provider} block has no client_secret; set {variable}")
        if not _MAIL_PASSWORD.fullmatch(client_secret):
            raise BootError(f"{variable} is not a client secret")
        block["client_secret"] = client_secret
        changed = True
    if not changed:
        return raw.encode("utf-8")
    return json.dumps(document).encode("utf-8")


def _materialize(
    environment: MutableMapping[str, str], directory: Path, files: BootFiles | None = None
) -> list[Path]:
    written: list[Path] = []
    # Validate before any material is replaced. The manifest has no credentials, but a
    # bad one must not silently turn a deployment into a permanent waitlist.
    runtime_document = _runtime_config(environment)
    key_files = _key_files(environment.get("EXECBOUND_COLLECTOR_KEY_FILES_JSON"))
    collector_keys = [
        (name, data)
        for variable, name in COLLECTOR_KEY_VARIABLES.items()
        if (data := _collector_key(variable, environment.get(variable))) is not None
    ]
    scout_app = _scout_app(environment.get("EXECBOUND_SCOUT_APP_JSON"))
    extra = [] if files is None else files(environment, directory, runtime_document)
    encoded = environment.get("SUPABASE_CA_B64")
    if encoded:
        try:
            bundle = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BootError("SUPABASE_CA_B64 is not base64") from None
        if not bundle:
            raise BootError("SUPABASE_CA_B64 is empty")
        _write(directory / CA_FILE, bundle)
        written.append(directory / CA_FILE)
    for name, target_name in (
        ("EXECBOUND_RUNTIME_CONFIG_JSON", "EXECBOUND_RUNTIME_CONFIG"),
        ("EXECBOUND_MOCK_ACCOUNTS_JSON", "EXECBOUND_MOCK_ACCOUNTS_PATH"),
    ):
        document = (
            runtime_document
            if name == "EXECBOUND_RUNTIME_CONFIG_JSON"
            else _json_document(environment, name)
        )
        if document is None:
            continue
        target = environment.get(target_name)
        if not target:
            raise BootError(f"{name} needs {target_name} to name its file")
        _write(Path(target), document)
        written.append(Path(target))
    token = environment.get("EXECBOUND_ADMIN_TOKEN")
    if token:
        if not _is_token(token):
            raise BootError("EXECBOUND_ADMIN_TOKEN is not a token")
        _write(directory / TOKEN_FILE, (token + "\n").encode("ascii"))
        _write(directory / MONITOR_FILE, json.dumps({"admin_token": token}).encode("ascii"))
        written.extend((directory / TOKEN_FILE, directory / MONITOR_FILE))
    jobs = environment.get("EXECBOUND_JOBS_TOKENS_JSON")
    if jobs:
        _write(directory / JOBS_FILE, _jobs_tokens(jobs))
        written.append(directory / JOBS_FILE)
    for name, data in key_files:
        path = directory / KEY_FILES / f"{name}.env"
        _write(path, data)
        written.append(path)
    for name, data in collector_keys:
        _write(directory / name, data)
        written.append(directory / name)
    if scout_app is not None:
        _write(directory / SCOUT_APP_FILE, scout_app)
        written.append(directory / SCOUT_APP_FILE)
    for path, data in extra:
        _write(path, data)
        written.append(path)
    return written


def _key_files(raw: str | None) -> list[tuple[str, bytes]]:
    """The collector's operator key files, checked to their shape and never printed: a JSON
    object of canonical connection id to the key file's text, printable ASCII and line breaks
    only. The id is the file's name, so it must be exactly a UUID and can name no other path."""
    if not raw:
        return []
    variable = "EXECBOUND_COLLECTOR_KEY_FILES_JSON"
    try:
        document = json.loads(raw)
    except ValueError:
        raise BootError(f"{variable} is not JSON") from None
    if type(document) is not dict or not 1 <= len(document) <= MAX_KEY_FILES:
        raise BootError(f"{variable} must map connection ids to key files")
    files = []
    for key, value in document.items():
        try:
            if str(UUID(str(key))) != key:
                raise ValueError
        except ValueError:
            raise BootError(f"{variable} has a malformed connection id") from None
        if (
            type(value) is not str
            or not 1 <= len(value) <= MAX_KEY_FILE_BYTES
            or not all(" " <= character <= "~" or character in "\r\n\t" for character in value)
        ):
            raise BootError(f"{variable} has a malformed key file")
        files.append((key, value.encode("ascii")))
    return files


def _collector_key(variable: str, raw: str | None) -> bytes | None:
    """A collector private key file, checked to be one (its id derived from its key) exactly as
    the collector reads it, a repeated name refused, and never printed."""
    if not raw:
        return None
    from execbound.monitoring.sealing import CollectorKeyError, parse_private_text

    try:
        parse_private_text(raw)
    except CollectorKeyError:
        raise BootError(f"{variable} is not a collector private key") from None
    return raw.encode("utf-8")


def _scout_app(raw: str | None) -> bytes | None:
    """The platform app's credential file, checked to be one exactly as the collector reads it
    (a repeated name refused, the certificate the key's), and never printed."""
    if not raw:
        return None
    from execbound.monitoring.graph import GraphError, PlatformApp

    try:
        PlatformApp.from_text(raw)
    except GraphError:
        raise BootError("EXECBOUND_SCOUT_APP_JSON is not a platform app credential") from None
    return raw.encode("utf-8")


def _jobs_tokens(raw: str) -> bytes:
    """The scheduled jobs' tenant-to-token map, checked to its shape and never printed."""
    try:
        document = json.loads(raw)
    except ValueError:
        raise BootError("EXECBOUND_JOBS_TOKENS_JSON is not JSON") from None
    if type(document) is not dict or not 1 <= len(document) <= MAX_JOB_TENANTS:
        raise BootError(f"EXECBOUND_JOBS_TOKENS_JSON must map 1 to {MAX_JOB_TENANTS} tenants")
    for key, value in document.items():
        try:
            if str(UUID(str(key))) != key:
                raise ValueError
        except ValueError:
            raise BootError("EXECBOUND_JOBS_TOKENS_JSON has a malformed tenant id") from None
        if not _is_token(value):
            raise BootError("EXECBOUND_JOBS_TOKENS_JSON has a malformed token")
    return json.dumps(document, sort_keys=True).encode("ascii")


def _resources(raw: str) -> list[tuple[UUID, UUID, str, UUID, str, bool, bool]]:
    try:
        entries = json.loads(raw)
    except ValueError:
        raise BootError("EXECBOUND_MOCK_RESOURCES_JSON is not JSON") from None
    if not isinstance(entries, list) or len(entries) > MAX_RESOURCES:
        raise BootError("EXECBOUND_MOCK_RESOURCES_JSON must be a list")
    parsed = []
    for index, item in enumerate(entries):
        if (
            not isinstance(item, dict)
            or not RESOURCE_KEYS <= set(item)
            or not set(item) <= RESOURCE_KEYS | RESOURCE_FLAGS
        ):
            raise BootError(f"EXECBOUND_MOCK_RESOURCES_JSON entry {index} has the wrong keys")
        try:
            tenant = UUID(str(item["tenant_id"]))
            account = UUID(str(item["account_id"]))
            canonical = UUID(str(item["canonical_target_id"]))
        except ValueError:
            raise BootError(
                f"EXECBOUND_MOCK_RESOURCES_JSON entry {index} has a malformed identifier"
            ) from None
        provider_id = item["provider_id"]
        version = item["version"]
        if (
            type(provider_id) is not str
            or not 0 < len(provider_id) <= 128
            or type(version) is not str
            or not 0 < len(version) <= 80
            or any(type(item[flag]) is not bool for flag in RESOURCE_FLAGS if flag in item)
        ):
            raise BootError(f"EXECBOUND_MOCK_RESOURCES_JSON entry {index} has a malformed value")
        parsed.append(
            (
                tenant,
                account,
                provider_id,
                canonical,
                version,
                bool(item.get("contained", False)),
                bool(item.get("account_enabled", True)),
            )
        )
    return parsed


def _provision(environment: MutableMapping[str, str]) -> int:
    raw = environment.get("EXECBOUND_MOCK_RESOURCES_JSON")
    if not raw:
        return 0
    path = environment.get("EXECBOUND_MOCK_DATABASE_PATH")
    if not path:
        raise BootError("EXECBOUND_MOCK_RESOURCES_JSON needs EXECBOUND_MOCK_DATABASE_PATH")
    provider = environment.get("EXECBOUND_MOCK_PROVIDER", "mock_crowdstrike")
    if provider not in PROVIDERS:
        raise BootError("EXECBOUND_MOCK_PROVIDER is not a mock provider")
    entries = _resources(raw)
    if provider == "mock_entra":
        from execbound.provider.identity_store import IdentityStore

        identities = IdentityStore(Path(path))
        for tenant, account, provider_id, canonical, version, _, enabled in entries:
            identities.provision_resource(tenant, canonical, version, account_enabled=enabled)
            identities.provision_representation(tenant, account, provider_id, canonical)
    else:
        from execbound.provider.mock_store import MockStore

        endpoints = MockStore(Path(path))
        for tenant, account, provider_id, canonical, version, contained, _ in entries:
            endpoints.provision_resource(tenant, canonical, version, contained=contained)
            endpoints.provision_representation(tenant, account, provider_id, canonical)
    return len(entries)


def reprovision(
    environment: MutableMapping[str, str],
    provider: str,
    tenant_id: UUID,
    canonical_target_id: UUID,
    *,
    version: str | None = None,
    reason: str = "",
) -> dict[str, str]:
    """Reset one mock target deliberately, from inside the mock's own environment (#350).

    Provisioning at start creates and never overwrites, so a target whose provider state
    has drifted from the gateway's inventory needs an explicit repair. This is it, and it
    touches exactly the one target named.

    **A stated `--version` changes the version and nothing else.** That is the case the
    repair exists for: a stranded target needs the version the inventory expects, while
    the containment or the disabled account it legitimately holds must survive — resetting
    those from the file would contradict the audit chain again, which is the whole defect.
    Without a version the target is reset to the file's values in full, which is the other
    thing an operator may mean, and the file must name it.
    """
    from execbound.logging_schema import log_event

    if provider not in ("endpoint", "identity"):
        raise BootError("Unknown mock provider")
    path = environment.get("EXECBOUND_MOCK_DATABASE_PATH")
    if not path:
        raise BootError("mock-reprovision needs EXECBOUND_MOCK_DATABASE_PATH")
    if version is not None and not 0 < len(version) <= 80:
        raise BootError("The stated version is outside the provider's bound")

    if provider == "identity":
        from execbound.provider.identity_store import IdentityStore

        store: Any = IdentityStore(Path(path))
    else:
        from execbound.provider.mock_store import MockStore

        store = MockStore(Path(path))
    current = store.resource(tenant_id, canonical_target_id)
    if current is None:
        # Nothing to reset: this repairs drift, and a target the mock never held has none.
        raise BootError("The mock holds no such target")

    if version is not None:
        # The repair case: the version the inventory expects, and nothing else touched.
        new_version, seeded_flag, keep = version, None, True
    else:
        seeded = _seeded_entry(environment, tenant_id, canonical_target_id)
        if seeded is None:
            raise BootError("Without --version the resources file has to name the target")
        new_version, seeded_flag, keep = seeded[0], seeded[1], False

    if provider == "identity":
        store.reprovision_resource(
            tenant_id,
            canonical_target_id,
            new_version,
            account_enabled=current.account_enabled if keep else seeded_flag,
            session_generation=current.session_generation if keep else 0,
        )
    else:
        store.reprovision_resource(
            tenant_id,
            canonical_target_id,
            new_version,
            contained=current.contained if keep else seeded_flag,
        )
    after = store.resource(tenant_id, canonical_target_id)
    assert after is not None
    log_event(
        "mock.reprovisioned",
        tenant_id=str(tenant_id),
        canonical_target_id=str(canonical_target_id),
        from_version=current.version,
        to_version=after.version,
        reason=reason or "unstated",
    )
    return {"from_version": current.version, "to_version": after.version}


def _seeded_entry(
    environment: MutableMapping[str, str], tenant_id: UUID, canonical_target_id: UUID
) -> tuple[str, bool] | None:
    """The file's version and its provider-specific flag for one target, if it names it."""
    raw = environment.get("EXECBOUND_MOCK_RESOURCES_JSON")
    if not raw:
        return None
    for tenant, _account, _provider_id, canonical, version, contained, enabled in _resources(raw):
        if tenant == tenant_id and canonical == canonical_target_id:
            provider = environment.get("EXECBOUND_MOCK_PROVIDER", "mock_crowdstrike")
            return version, enabled if provider == "mock_entra" else contained
    return None


def _expand(argument: str, environment: MutableMapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        value = environment.get(name)
        if value is None:
            raise BootError(f"{name} is not set")
        return value

    return _VARIABLE.sub(replace, argument)


def _execute(program: str, arguments: Sequence[str]) -> None:
    os.execvp(program, list(arguments))  # nosec B606 - the configured process, no shell


def run(
    arguments: Sequence[str],
    environment: MutableMapping[str, str] | None = None,
    *,
    execute: Callable[[str, Sequence[str]], object] = _execute,
    files: BootFiles | None = None,
    consumed: tuple[str, ...] = (),
) -> int:
    """Materialize, provision, scrub and exec. Returns the provisioned count only when the
    supplied `execute` returns, which the real one never does."""
    env = os.environ if environment is None else environment
    if not arguments:
        raise BootError("no command to start")
    os.umask(0o077)
    directory = Path(env.get("EXECBOUND_BOOT_DIR") or DEFAULT_DIRECTORY)
    _materialize(env, directory, files)
    provisioned = _provision(env)
    command = [_expand(argument, env) for argument in arguments]
    for name in (*CONSUMED, *consumed, *WITHHELD):
        env.pop(name, None)
    try:
        execute(command[0], command)
    except FileNotFoundError:
        raise BootError(f"{command[0]} is not on PATH") from None
    return provisioned


def main(argv: Sequence[str] | None = None) -> None:
    try:
        run(sys.argv[1:] if argv is None else argv)
    except BootError as exc:
        print(f"boot: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
