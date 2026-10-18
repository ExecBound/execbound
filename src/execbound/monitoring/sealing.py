# SPDX-License-Identifier: AGPL-3.0-only
"""A monitoring key sealed to the collector's own key (#228, #678).

An administrator pastes a Tines API key into the console once. The gateway seals it to the
collector's public key and keeps the ciphertext on the connection row (`sealed_ct`); only the
collector's private key opens it, so the web service can write a key and never read one back.

Sealing is libsodium's sealed box (X25519 with XSalsa20-Poly1305) through PyNaCl, as #153
specifies for executor credentials; nothing here designs cryptography of its own. A sealed box
carries no additional authenticated data, so what is sealed is an envelope that binds the key to
its row: the canonical JSON of `{"v": 1, "purpose": "collector", "tenant_id", "connection_id",
"kind", "key"}`. The collector opens it and refuses (`SEALED_KEY_MISMATCH`) unless every one of
those names the row it is collecting, so a ciphertext copied to another connection or another
tenant opens and is refused rather than used.

A collector key pair is two owner-only files, written by `collector-keygen`:
`collector-public.json` (`{"key_id", "public_key"}`) for the gateway's runtime configuration and
`collector-private.json` (`{"key_id", "private_key"}`) for the collector's environment alone.
The key id is `ck1-` and the first sixteen hex digits of the SHA-256 of the public key, so it is
derived, never chosen.

The gateway imports `seal_for_collector`, `read_public_key`, `CollectorPublicKey` and the key's
shape, `API_KEY`, and nothing else from here (`tests/test_monitor_sealing.py` holds every module
to that); the private-key readers and `open_for_collector` are the collector's commands' alone.
No message here quotes a key, a ciphertext or a file's contents.
"""

import base64
import binascii
import hashlib
import json
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

from execbound.monitoring.models import MonitorError

KEY_ID = re.compile(r"ck1-[0-9a-f]{16}")
PUBLIC_FILE = "collector-public.json"
PRIVATE_FILE = "collector-private.json"
PURPOSE = "collector"
VERSION = 1
KEY_BYTES = 32
MAX_KEY_FILE_BYTES = 4096
# What a pasted key may be: printable ASCII with no whitespace, as `api_key` is bounded where it
# is entered.
API_KEY = re.compile(r"[\x21-\x7e]{1,4096}")
ENVELOPE_KEYS = frozenset({"v", "purpose", "tenant_id", "connection_id", "kind", "key"})


class CollectorKeyError(ValueError):
    """A collector key file or block that is not one; names a field, never a value."""


def key_id(public_key: bytes) -> str:
    """`ck1-` and the first sixteen hex digits of the SHA-256 of an X25519 public key."""
    return "ck1-" + hashlib.sha256(public_key).hexdigest()[:16]


def _decode(value: object, field: str) -> bytes:
    """A 32-byte key, in base64 with padding and in exactly one spelling."""
    if type(value) is not str or len(value) > 64:
        raise CollectorKeyError(f"{field} is not a base64 X25519 key")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise CollectorKeyError(f"{field} is not a base64 X25519 key") from None
    if len(raw) != KEY_BYTES or base64.b64encode(raw).decode("ascii") != value:
        raise CollectorKeyError(f"{field} is not a base64 X25519 key")
    return raw


@dataclass(frozen=True)
class CollectorPublicKey:
    """The collector's public key and its derived id: what the gateway seals to."""

    key_id: str
    public_key: bytes

    def __post_init__(self) -> None:
        if type(self.public_key) is not bytes or len(self.public_key) != KEY_BYTES:
            raise CollectorKeyError("public_key is not an X25519 key")
        if type(self.key_id) is not str or self.key_id != key_id(self.public_key):
            raise CollectorKeyError("key_id does not match its public key")

    def document(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
        }


def read_public_key(document: Mapping[str, Any]) -> CollectorPublicKey:
    """`{"key_id", "public_key"}` from a configuration block or `collector-public.json`."""
    if not isinstance(document, Mapping) or set(document) != {"key_id", "public_key"}:
        raise CollectorKeyError("A collector public key has exactly key_id and public_key")
    raw = _decode(document["public_key"], "public_key")
    if document["key_id"] != key_id(raw):
        raise CollectorKeyError("key_id does not match its public key")
    return CollectorPublicKey(key_id(raw), raw)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _seal_bytes(public: CollectorPublicKey, plaintext: bytes) -> bytes:
    return bytes(SealedBox(PublicKey(public.public_key)).encrypt(plaintext))


def seal_for_collector(
    public: CollectorPublicKey, tenant: UUID, connection: UUID, kind: str, key: str
) -> bytes:
    """The key, bound to its tenant, connection and kind, sealed to the collector's key."""
    if (
        type(public) is not CollectorPublicKey
        or type(tenant) is not UUID
        or type(connection) is not UUID
        or kind != "tines"
        or type(key) is not str
        or API_KEY.fullmatch(key) is None
    ):
        raise MonitorError("INVALID_INPUT")
    envelope = {
        "v": VERSION,
        "purpose": PURPOSE,
        "tenant_id": str(tenant),
        "connection_id": str(connection),
        "kind": kind,
        "key": key,
    }
    return _seal_bytes(public, _canonical(envelope))


@dataclass(frozen=True)
class CollectorKeyRing:
    """The collector's private keys by id. Its representation names the ids, never a key."""

    keys: Mapping[str, PrivateKey] = field(repr=False)

    def __repr__(self) -> str:
        return f"CollectorKeyRing({sorted(self.keys)!r})"

    def key_ids(self) -> Iterator[str]:
        return iter(sorted(self.keys))

    def get(self, identifier: object) -> PrivateKey | None:
        return self.keys.get(identifier) if type(identifier) is str else None

    def private_bytes(self, identifier: str) -> bytes:
        return bytes(self.keys[identifier])

    def public_key(self, identifier: str) -> CollectorPublicKey:
        raw = bytes(self.keys[identifier].public_key)
        return CollectorPublicKey(key_id(raw), raw)


def _read_document(path: Path) -> object:
    try:
        raw = path.read_bytes()
    except OSError:
        raise CollectorKeyError("The collector key file cannot be read") from None
    if not 0 < len(raw) <= MAX_KEY_FILE_BYTES:
        raise CollectorKeyError("The collector key file is not one")
    try:
        return _parse(raw.decode("utf-8"))
    except ValueError:
        raise CollectorKeyError("The collector key file is not JSON") from None


def _parse(raw: str) -> object:
    """JSON that names no member twice: a key file whose second `private_key` silently won
    would be a different key from the one its reader checked."""
    return json.loads(raw, object_pairs_hook=_unique)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_private_document(document: object) -> CollectorKeyRing:
    """`{"key_id", "private_key"}`: one private key, whose public key's id it names."""
    if not isinstance(document, dict) or set(document) != {"key_id", "private_key"}:
        raise CollectorKeyError("A collector private key has exactly key_id and private_key")
    key = PrivateKey(_decode(document["private_key"], "private_key"))
    identifier = key_id(bytes(key.public_key))
    if document["key_id"] != identifier:
        raise CollectorKeyError("key_id does not match its private key")
    return CollectorKeyRing({identifier: key})


def parse_private_text(raw: str) -> CollectorKeyRing:
    """A private key file's text, read exactly as `read_private_file` reads the file, so a
    document boot writes is one the collector opens."""
    if len(raw.encode("utf-8")) > MAX_KEY_FILE_BYTES:
        raise CollectorKeyError("The collector key file is not one")
    try:
        document = _parse(raw)
    except ValueError:
        raise CollectorKeyError("The collector key file is not JSON") from None
    return parse_private_document(document)


def read_private_file(path: Path) -> CollectorKeyRing:
    """`collector-private.json`, as `collector-keygen` wrote it."""
    return parse_private_document(_read_document(path))


def combine(rings: Iterable[CollectorKeyRing]) -> CollectorKeyRing:
    """One ring of every key in `rings`: during a rotation the collector holds the key being
    retired beside the new one, and opens a connection sealed to either. A key given twice is
    one key; two different keys under one id are refused, naming neither."""
    keys: dict[str, PrivateKey] = {}
    for ring in rings:
        for identifier in ring.key_ids():
            key = ring.keys[identifier]
            held = keys.get(identifier)
            if key_id(bytes(key.public_key)) != identifier or (
                held is not None and bytes(held) != bytes(key)
            ):
                raise CollectorKeyError("Two collector keys claim one key id")
            keys[identifier] = key
    return CollectorKeyRing(keys)


def read_public_file(path: Path) -> CollectorPublicKey:
    """`collector-public.json`, or the public half of `collector-private.json`."""
    document = _read_document(path)
    if isinstance(document, dict) and "private_key" in document:
        ring = parse_private_document(document)
        return ring.public_key(next(ring.key_ids()))
    if not isinstance(document, dict):
        raise CollectorKeyError("A collector public key has exactly key_id and public_key")
    return read_public_key(document)


def _private_opener(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


def generate(output: Path) -> CollectorPublicKey:
    """`collector-keygen`: a new key pair as two owner-only files in `output`, refusing a
    directory that already holds either."""
    public_path, private_path = output / PUBLIC_FILE, output / PRIVATE_FILE
    if public_path.exists() or private_path.exists():
        raise FileExistsError(PUBLIC_FILE if public_path.exists() else PRIVATE_FILE)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = PrivateKey.generate()
    public = CollectorPublicKey(key_id(bytes(key.public_key)), bytes(key.public_key))
    private = {
        "key_id": public.key_id,
        "private_key": base64.b64encode(bytes(key)).decode("ascii"),
    }
    written: list[Path] = []
    try:
        for path, document in ((private_path, private), (public_path, public.document())):
            with open(str(path), "x", encoding="utf-8", opener=_private_opener) as handle:
                written.append(path)
                json.dump(document, handle, indent=2)
                handle.write("\n")
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    return public


def open_for_collector(ring: CollectorKeyRing, row: Mapping[str, Any]) -> str:
    """The key sealed on `row`, for the collector's run against that row and no other.

    `COLLECTOR_KEY_UNAVAILABLE` when the ring holds no key for the row's key id or the key it
    holds does not open the ciphertext; `SEALED_KEY_MISMATCH` when the envelope opens and names
    another tenant, connection or kind, or is not exactly the collector's envelope.
    """
    if type(ring) is not CollectorKeyRing or row.get("credential_mode") != "sealed":
        raise MonitorError("COLLECTOR_KEY_UNAVAILABLE")
    key = ring.get(row.get("sealed_key_id"))
    ciphertext = row.get("sealed_ct")
    if key is None or not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise MonitorError("COLLECTOR_KEY_UNAVAILABLE")
    try:
        plaintext = SealedBox(key).decrypt(bytes(ciphertext))
    except CryptoError:
        raise MonitorError("COLLECTOR_KEY_UNAVAILABLE") from None
    try:
        envelope = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_unique)
    except ValueError:
        raise MonitorError("SEALED_KEY_MISMATCH") from None
    if (
        not isinstance(envelope, dict)
        or set(envelope) != ENVELOPE_KEYS
        or type(envelope["v"]) is not int
        or envelope["v"] != VERSION
        or envelope["purpose"] != PURPOSE
        or envelope["tenant_id"] != str(row.get("tenant_id"))
        or envelope["connection_id"] != str(row.get("connection_id"))
        or envelope["kind"] != row.get("kind")
        or type(envelope["key"]) is not str
        or API_KEY.fullmatch(envelope["key"]) is None
    ):
        raise MonitorError("SEALED_KEY_MISMATCH")
    return str(envelope["key"])
