# SPDX-License-Identifier: AGPL-3.0-only
"""A secret a tenant gave this deployment, at rest: AES-256-GCM under a deployment key ring.

Regular sign-in (#429) put each provider's client secret in the environment, one variable per
provider, because a deployment has exactly one Google client and the person who created it is
the person who runs the server. A customer's own identity provider is not like that: its
administrator registers it from a browser at a moment nobody chose, there is no restart to put
a variable in, and one environment variable per customer is not something an administrator can
do at all. So the secret is a column, and the column holds ciphertext.

What that buys: the key is in the private configuration, outside the database and outside the
protected agent's read and write authority, so a database read on its own — a copied backup, a
replica, a query that reaches a `SELECT` — yields ciphertext and nothing else. What it does not
buy: a process that can already read the gateway's configuration can open every tenant's
secret, which is exactly where the mock connector tokens and the assistant key already are.

The additional authenticated data names the tenant, the provider and the purpose, so a
ciphertext moved to another tenant's row, another provider's row or the refresh-token column
does not open. Rotation is the active key changing: an old key stays in the ring so existing
rows keep opening, and a row is rewritten under the active one the next time it is written.

Nothing here is ever logged, rendered or returned to a caller. A failure carries a code and
never the value, the key id or the length of anything.
"""

import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
# The longest plaintext this will seal. A client secret is well under a hundred bytes and a
# refresh token a few thousand; the bound is here so a provider cannot make this server store
# an arbitrary amount of its own text.
MAX_PLAINTEXT = 8192
MAX_CIPHERTEXT_HEX = 2 * (NONCE_BYTES + MAX_PLAINTEXT + TAG_BYTES)
_KEY_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_HEX = re.compile(r"[0-9a-f]+")
PURPOSES = frozenset({"client_secret", "refresh_token", "authenticator_seed"})


class EnvelopeError(ValueError):
    """A safe code; no key, no key id, no ciphertext and no plaintext reaches a message."""

    def __init__(self, code: str = "ENVELOPE_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Envelope unavailable")


@dataclass(frozen=True)
class KeyRing:
    """The deployment's sealing keys: one active, and every key a stored row may name.

    Copied on construction, exactly as `TokenKeys` is, so a mapping the caller keeps a handle
    to cannot change which key opens a row afterwards.
    """

    active_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.active_key_id) is not str
            or _KEY_ID.fullmatch(self.active_key_id) is None
            or not isinstance(self.keys, Mapping)
        ):
            raise ValueError("Invalid envelope keys")
        copied = dict(self.keys)
        if self.active_key_id not in copied or any(
            type(key_id) is not str
            or _KEY_ID.fullmatch(key_id) is None
            or type(key) is not bytes
            or len(key) != KEY_BYTES
            for key_id, key in copied.items()
        ):
            raise ValueError("Invalid envelope keys")
        object.__setattr__(self, "keys", copied)

    def __repr__(self) -> str:
        return f"KeyRing(active_key_id={self.active_key_id!r}, keys=<{len(self.keys)}>)"

    def key(self, key_id: object) -> bytes:
        if type(key_id) is not str or key_id not in self.keys:
            raise EnvelopeError("UNKNOWN_KEY")
        return self.keys[key_id]


def context(tenant_id: UUID, provider_id: UUID, purpose: str) -> bytes:
    """What a sealed value is bound to. A row that moves does not open."""
    if purpose not in PURPOSES:
        raise EnvelopeError("INVALID_PURPOSE")
    return f"{tenant_id}|{provider_id}|{purpose}".encode("ascii")


def seal(
    ring: KeyRing, plaintext: str, tenant_id: UUID, provider_id: UUID, purpose: str
) -> tuple[str, str]:
    """Seal under the ring's active key; the nonce, the ciphertext and the tag as one hex value."""
    if type(plaintext) is not str or not 0 < len(plaintext.encode("utf-8")) <= MAX_PLAINTEXT:
        raise EnvelopeError("INVALID_PLAINTEXT")
    nonce = secrets.token_bytes(NONCE_BYTES)
    key_id = ring.active_key_id
    sealed = AESGCM(ring.key(key_id)).encrypt(
        nonce, plaintext.encode("utf-8"), context(tenant_id, provider_id, purpose)
    )
    return (nonce + sealed).hex(), key_id


def unseal(
    ring: KeyRing,
    ciphertext: object,
    key_id: object,
    tenant_id: UUID,
    provider_id: UUID,
    purpose: str,
) -> str:
    """The plaintext, or a refusal. A retired key and a moved row fail the same way."""
    if (
        type(ciphertext) is not str
        or not 2 * (NONCE_BYTES + TAG_BYTES) <= len(ciphertext) <= MAX_CIPHERTEXT_HEX
        or len(ciphertext) % 2
        or _HEX.fullmatch(ciphertext) is None
    ):
        raise EnvelopeError("INVALID_CIPHERTEXT")
    raw = bytes.fromhex(ciphertext)
    try:
        opened = AESGCM(ring.key(key_id)).decrypt(
            raw[:NONCE_BYTES], raw[NONCE_BYTES:], context(tenant_id, provider_id, purpose)
        )
        return opened.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError):
        raise EnvelopeError("INVALID_CIPHERTEXT") from None


def ring_from(block: Any) -> KeyRing:
    """The ring a private configuration block names.

    A deployment given no ring can hold no tenant's secret, so the caller answers None before
    reaching here: the console then registers no provider and says so rather than offering a
    form that cannot work.
    """
    return KeyRing(
        block.active_key_id,
        {name: bytes.fromhex(value.get_secret_value()) for name, value in block.keys.items()},
    )
