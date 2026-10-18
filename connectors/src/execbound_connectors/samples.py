# SPDX-License-Identifier: Apache-2.0
"""Sample accounts (#420): one sample key, and every workspace's own mock connection from it.

An account the `samples_install` function marked `sample` has no configured connector and no
configured mock account. The gateway and the endpoint mock each derive the account's dispatch
token, control token and journal-signing key from the provider's sample key, the account's
tenant and its id. Nothing is stored and nothing per workspace is configured: both sides compute
the same values independently, and because the derivation binds the tenant and the account, a
token for one workspace or account fails for any other.

Each value is HMAC-SHA256 of the sample key over a fixed domain, the label and the two ids'
sixteen raw bytes, with a NUL byte after the domain and after the label. The labels are fixed
ASCII words with no NUL and the ids are fixed length, so no two inputs share an encoding.
Tokens take the form `provider_material` gives a generated token (URL-safe base64 of 32 bytes,
43 characters, no padding); the journal key is the 32 bytes themselves, the length a generated
signing key has, under the key id `sample-v1`.
"""

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from execbound_protocol.catalog import ProviderName

from execbound_connectors.accounts import (
    ProviderAccount,
)
from execbound_connectors.mock import ConnectionConfig

SampleLabel = Literal["dispatch", "control", "journal"]

# The only provider sample accounts are derived for; identity samples would first need identity
# rules in the starter ruleset.
SAMPLE_PROVIDER: Literal["mock_crowdstrike"] = "mock_crowdstrike"
SAMPLE_KEY_ID = "sample-v1"
# The version ExecBound's sample facts record for every sample target, and the version the mock
# creates a sample target at the first time a command names it.
SAMPLE_RESOURCE_VERSION = "sample-resource-v1"
MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 128
_DOMAIN = b"execbound/sample-account/v1"
_LABELS: frozenset[str] = frozenset({"dispatch", "control", "journal"})
_HEX = re.compile(r"(?:[0-9a-f]{2}){32,128}")


def parse_sample_key(value: object) -> bytes:
    """A sample key from its lower-case hex form, 32 to 128 bytes; anything else is refused."""
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError("Invalid sample key")
    return bytes.fromhex(value)


def derive(key: bytes, label: SampleLabel, tenant_id: UUID, account_id: UUID) -> bytes:
    """HMAC-SHA256 of the sample key over the domain, the label, the tenant and the account."""
    if (
        type(key) is not bytes
        or not MIN_KEY_BYTES <= len(key) <= MAX_KEY_BYTES
        or label not in _LABELS
        or type(tenant_id) is not UUID
        or type(account_id) is not UUID
    ):
        raise ValueError("Invalid sample derivation")
    message = (
        _DOMAIN + b"\x00" + label.encode("ascii") + b"\x00" + tenant_id.bytes + account_id.bytes
    )
    return hmac.new(key, message, hashlib.sha256).digest()


def _token(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SampleMaterial:
    """One sample account's secrets, held in memory for one use and written nowhere."""

    dispatch_token: str = field(repr=False)
    control_token: str = field(repr=False)
    journal_key: bytes = field(repr=False)


def sample_material(key: bytes, tenant_id: UUID, account_id: UUID) -> SampleMaterial:
    return SampleMaterial(
        _token(derive(key, "dispatch", tenant_id, account_id)),
        _token(derive(key, "control", tenant_id, account_id)),
        derive(key, "journal", tenant_id, account_id),
    )


def sample_account(key: bytes, tenant_id: UUID, account_id: UUID) -> ProviderAccount:
    """The mock's record of one sample account: token digests and the derived journal key."""
    material = sample_material(key, tenant_id, account_id)
    return ProviderAccount(
        tenant_id=tenant_id,
        account_id=account_id,
        dispatch_token_hash=hashlib.sha256(material.dispatch_token.encode("ascii")).hexdigest(),
        control_token_hash=hashlib.sha256(material.control_token.encode("ascii")).hexdigest(),
        signing_key=material.journal_key,
        key_id=SAMPLE_KEY_ID,
        provider=SAMPLE_PROVIDER,
    )


@dataclass(frozen=True)
class SampleProvider:
    """One `sample_providers` entry: the mock's configured origin and its sample key.

    The origin is checked by deriving a connection with it, so a sample origin obeys exactly
    the rules a configured connector's does: HTTPS, or cleartext to a loopback IP address only.
    """

    provider: ProviderName
    origin: str
    key: bytes = field(repr=False)
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.provider != SAMPLE_PROVIDER:
            raise ValueError("Invalid sample provider")
        sample_connection(self, UUID(int=1), UUID(int=2))


def sample_connection(
    provider: SampleProvider, tenant_id: UUID, account_id: UUID
) -> ConnectionConfig:
    """The gateway's connection for one sample account: the configured origin, derived secrets."""
    material = sample_material(provider.key, tenant_id, account_id)
    return ConnectionConfig(
        tenant_id,
        account_id,
        provider.origin,
        material.dispatch_token,
        material.control_token,
        {SAMPLE_KEY_ID: material.journal_key},
        provider.timeout_seconds,
        provider=provider.provider,
    )
