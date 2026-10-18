# SPDX-License-Identifier: Apache-2.0
"""The mock connector: one configured origin, two bearer tokens, one HTTP attempt.

It posts the frozen `ProviderCommand` to a mock vendor and returns the journal the vendor
signed, after checking it against its own ring with the protocol's `check_journal`. The
server settles the journal with its own verifier (#496).
"""

import dataclasses
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from execbound_protocol.catalog import ProviderName
from execbound_protocol.connector import check_journal
from execbound_protocol.provider import MAX_PROVIDER_BYTES, ProviderCommand, ProviderError


@dataclass(frozen=True)
class ConnectionConfig:
    tenant_id: UUID
    account_id: UUID
    origin: str
    dispatch_token: str = field(repr=False)
    control_token: str = field(repr=False)
    evidence_keys: Mapping[str, bytes] = field(repr=False)
    timeout_seconds: float = 5.0
    provider: ProviderName = "mock_crowdstrike"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.origin)
        if (
            self.provider not in {"mock_crowdstrike", "mock_entra"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or not parsed.hostname
            or parsed.scheme not in {"http", "https"}
            or not 0 < self.timeout_seconds <= 30
        ):
            raise ValueError("Invalid provider connection")
        if parsed.scheme == "http":
            try:
                if not ipaddress.ip_address(parsed.hostname).is_loopback:
                    raise ValueError()
            except ValueError:
                raise ValueError("Cleartext provider connections require a loopback IP") from None
        if (
            not 16 <= len(self.dispatch_token) <= 256
            or not 16 <= len(self.control_token) <= 256
            or self.dispatch_token == self.control_token
            or not self.evidence_keys
            or any(len(key) < 32 for key in self.evidence_keys.values())
        ):
            raise ValueError("Invalid provider credentials")
        _ = parsed.port
        object.__setattr__(self, "evidence_keys", MappingProxyType(dict(self.evidence_keys)))
        object.__setattr__(self, "origin", self.origin.rstrip("/"))

    @property
    def secrets(self) -> frozenset[str]:
        return frozenset({self.dispatch_token, self.control_token})

    def with_keys(self, evidence_keys: Mapping[str, bytes]) -> "ConnectionConfig":
        return dataclasses.replace(self, evidence_keys=evidence_keys)


class MockConnector:
    def __init__(self, config: ConnectionConfig) -> None:
        config.__post_init__()
        self.config = config
        self._client = httpx.Client(
            transport=httpx.HTTPTransport(retries=0, trust_env=False),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(config.timeout_seconds),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )

    def rotate_keys(self, evidence_keys: Mapping[str, bytes]) -> None:
        """Replace the verification ring; outstanding proofs need their key to stay in it."""
        self.config = dataclasses.replace(self.config, evidence_keys=evidence_keys)

    def close(self) -> None:
        self._client.close()

    def _call(self, path: str, provider: ProviderCommand, *, control: bool = False) -> bytes | None:
        if (
            provider.tenant_id != self.config.tenant_id
            or provider.account_id != self.config.account_id
            or provider.provider != self.config.provider
        ):
            raise ProviderError("INVALID_SCOPE")
        try:
            token = self.config.control_token if control else self.config.dispatch_token
            with self._client.stream(
                "POST",
                self.config.origin + path,
                content=provider.model_dump_json().encode(),
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            ) as response:
                if path == "/v1/journal" and response.status_code == 404:
                    return None
                if (
                    response.status_code != 200
                    or response.headers.get("content-encoding", "identity") != "identity"
                    or response.headers.get("content-type", "").split(";")[0] != "application/json"
                ):
                    raise ProviderError("INVALID_RESPONSE")
                chunks = []
                size = 0
                for chunk in response.iter_bytes(chunk_size=4096):
                    size += len(chunk)
                    if size > MAX_PROVIDER_BYTES:
                        raise ProviderError("INVALID_RESPONSE")
                    chunks.append(chunk)
                evidence = b"".join(chunks)
            # Checked here, before it is returned, so a binding mistake is caught where it
            # was made; the server verifies it again, with its own verifier, to settle.
            check_journal(
                provider,
                evidence,
                self.config.evidence_keys,
                tenant_id=self.config.tenant_id,
                account_id=self.config.account_id,
                provider=self.config.provider,
            )
            return evidence
        except ProviderError:
            raise
        except (httpx.HTTPError, ValueError):
            raise ProviderError() from None

    def dispatch(self, command: ProviderCommand) -> bytes:
        result = self._call("/v1/" + command.provider_operation, command)
        assert result is not None
        return result

    def lookup(self, command: ProviderCommand) -> bytes | None:
        return self._call("/v1/journal", command)

    def cancel(self, command: ProviderCommand) -> bytes:
        result = self._call("/v1/cancel", command, control=True)
        assert result is not None
        return result
