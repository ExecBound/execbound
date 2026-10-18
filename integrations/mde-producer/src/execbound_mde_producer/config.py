# SPDX-License-Identifier: Apache-2.0
"""The producer's configuration and the two secret files it names.

Both secrets, the Defender application's client secret and the producer's `sg1.` token, stay
in their own files, readable by their owner alone, and outside the protected agent's reach.
The configuration names them and never holds them.
"""

import json
import re
import stat
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

MIN_INTERVAL, MAX_INTERVAL = 15, 240
MAX_HOSTS = 500
KEYS = {"gateway", "token_file", "defender_env", "account_id", "provider", "resource_type", "hosts"}
OPTIONAL = {"interval_seconds"}


class ConfigError(ValueError):
    """The configuration or a file it names is refused. The message never holds a secret."""


@dataclass(frozen=True)
class CoveredHost:
    # Matched case-insensitively to Defender's `vmMetadata.resourceId` (#478).
    azure_resource_id: str
    # The resource ExecBound registered for the host, on the provider it dispatches to.
    provider_id: str


@dataclass(frozen=True)
class Config:
    gateway: str
    token_file: Path
    defender_env: Path
    account_id: UUID
    provider: str
    resource_type: str
    hosts: tuple[CoveredHost, ...]
    interval_seconds: int = 60


def _loopback(host: str | None) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host or "").is_loopback
    except ValueError:
        return False


def private_file(path: Path) -> Path:
    try:
        mode = path.stat().st_mode
    except OSError:
        raise ConfigError(f"Unreadable file: {path.name}") from None
    if not stat.S_ISREG(mode) or mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"Not a private file: {path.name}")
    return path


def _gateway(value: Any) -> str:
    if type(value) is not str or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ConfigError("Invalid gateway")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ConfigError("Invalid gateway") from None
    if (
        parts.scheme not in {"https", "http"}
        or not host
        or port == 0
        or (parts.scheme == "http" and not _loopback(parts.hostname))
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or parts.username is not None
        or parts.password is not None
    ):
        raise ConfigError("Invalid gateway")
    return value.rstrip("/")


def _hosts(value: Any) -> tuple[CoveredHost, ...]:
    if type(value) is not list or not 1 <= len(value) <= MAX_HOSTS:
        raise ConfigError("Invalid hosts")
    hosts: list[CoveredHost] = []
    for item in value:
        if (
            type(item) is not dict
            or set(item) != {"azure_resource_id", "provider_id"}
            or type(item["azure_resource_id"]) is not str
            or not item["azure_resource_id"].startswith("/subscriptions/")
            or type(item["provider_id"]) is not str
            or not 1 <= len(item["provider_id"]) <= 128
        ):
            raise ConfigError("Invalid host")
        hosts.append(CoveredHost(item["azure_resource_id"], item["provider_id"]))
    resources = [host.azure_resource_id.casefold() for host in hosts]
    providers = [host.provider_id for host in hosts]
    if len(set(resources)) != len(resources) or len(set(providers)) != len(providers):
        raise ConfigError("Two hosts share a resource or a provider id")
    return tuple(hosts)


def load(path: Path) -> Config:
    # The configuration names the secret files and holds no secret, so it need not be private.
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ConfigError("Unreadable configuration") from None
    if type(raw) is not dict or not KEYS <= set(raw) <= KEYS | OPTIONAL:
        raise ConfigError("Invalid configuration keys")
    interval = raw.get("interval_seconds", 60)
    if type(interval) is not int or not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise ConfigError("Invalid interval")
    try:
        if type(raw["account_id"]) is not str:
            raise ValueError
        account = UUID(raw["account_id"])
    except (TypeError, ValueError):
        raise ConfigError("Invalid account") from None
    for name in ("provider", "resource_type"):
        if type(raw[name]) is not str or not raw[name]:
            raise ConfigError(f"Invalid {name}")
    for name in ("token_file", "defender_env"):
        if type(raw[name]) is not str or not raw[name] or "\x00" in raw[name]:
            raise ConfigError(f"Invalid {name}")
    base = path.parent
    return Config(
        gateway=_gateway(raw["gateway"]),
        token_file=private_file(base / raw["token_file"]),
        defender_env=private_file(base / raw["defender_env"]),
        account_id=account,
        provider=raw["provider"],
        resource_type=raw["resource_type"],
        hosts=_hosts(raw["hosts"]),
        interval_seconds=interval,
    )


def read_env(path: Path) -> dict[str, str]:
    """KEY=VALUE lines from a private file; the values are never printed."""
    values: dict[str, str] = {}
    for line in _read_private(path, "utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def read_token(path: Path) -> str:
    token = _read_private(path, "ascii").strip()
    if re.fullmatch(r"sg1\.[A-Za-z0-9_.-]{1,159}", token) is None:
        raise ConfigError("Not a producer token")
    return token


def _read_private(path: Path, encoding: str) -> str:
    try:
        with private_file(path).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ConfigError("Secret file too large")
        return raw.decode(encoding)
    except (OSError, UnicodeError):
        raise ConfigError("Unreadable secret file") from None
