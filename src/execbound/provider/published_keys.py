# SPDX-License-Identifier: AGPL-3.0-only
"""The executor protocol's and replay's published test keys, which ExecBound never accepts.

The protocol publishes key material that anyone holds, so that an executor can be checked
without a key of its own (`protocol/executor/v1/vectors/`): chapter 1's contract vectors are
signed under one journal key, their `test_verification_key_hex`, and chapter 2's checkpoint
report vectors publish an Ed25519 and an ES256 executor key with their private halves, and a
journal key. The vectors' executor (`tests/checkpoint_vectors.py`) also signs the refusals with
three keys outside every ring, written as byte runs, and the vector file publishes those
signatures; those keys are refused too. So is the journal key replay's regression fixtures are
re-signed under, which `replay.sanitize` publishes as `FIXTURE_JOURNAL_KEY`. A key anyone holds
authenticates nobody, so these are refused wherever a key becomes authority (#37):

- `administration._public_key` refuses a published executor key at registration and rotation,
  as `INVALID_KEY`, after normalizing it, so no spelling of one is stored;
- `ExecutorVerifier` lets a published key already in a ring attest nothing, whatever the grant,
  so a report signed with one is `INVALID_RECORD` and settles nothing, while
  `runtime.attestable_ring` and `policy.store.LIVE_EXECUTOR_KEY` do not count one as a key a
  grant could be attested by;
- `Runtime` refuses a published key as any connector's evidence key, any Gate account's journal
  key or any sample key, when it is built and on every key reload, so no deployment holds one.

A journal key is an HMAC-SHA256 key, and HMAC does not use a key as written: one longer than
the hash's 64-byte block is replaced by its SHA-256, and the result is padded with zero bytes to
the block. `000102…1f` followed by a zero byte is therefore the same key as chapter 1's, and
verifies every journal signed under it. So a key is compared in that form, `hmac_key`, and
never as the bytes it was written in.

The keys are held here as values rather than read from the vector files, because those files
are not part of an installed server. `tests/test_published_test_keys.py` holds both sets equal
to every key the vector files publish, every byte-run key the vectors' executor signs with and
the replay fixture key, so none of them can publish a key ExecBound would accept.
"""

import hashlib
import re

# The block of SHA-256, which HMAC pads a key to.
_BLOCK = 64
_HEX = re.compile(r"[0-9a-f]+")

# Executor public keys as `executor_keys.public_key` stores them, lowercase hex: an Ed25519
# key's thirty-two raw bytes, and an ES256 key's compressed SEC1 point, which registration
# normalizes a PEM or a JWK of the same key to.
PUBLISHED_EXECUTOR_KEYS: frozenset[str] = frozenset(
    {
        # Chapter 2, `conformance-ed25519`.
        "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d",
        # Chapter 2, `conformance-es256`.
        "02bf97d0ee1866aac6f80826ebadc42f3d81e1b6b8f298f5d3ebe7542b7cb483a7",
        # The vectors' executor's Ed25519 key outside every ring, `OUTSIDE_ED25519_SEED`.
        "cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa",
        # The vectors' executor's ES256 key outside every ring, `OUTSIDE_ES256_SCALAR`.
        "020d0918a04198474605615b6df90fdcb34791fb3ecb822f4b26eb6e4fc4511b9d",
    }
)

# Journal keys, HMAC-SHA256 keys that verify a provider's signed journal, as written.
PUBLISHED_JOURNAL_KEYS: frozenset[bytes] = frozenset(
    {
        # Chapter 1, every contract vector's `test_verification_key_hex`.
        bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        # Chapter 2, `conformance-journal`.
        bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"),
        # The vectors' executor's journal key outside every ring, `OUTSIDE_JOURNAL_KEY`.
        bytes.fromhex("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        # The key replay's regression fixtures are re-signed under, `FIXTURE_JOURNAL_KEY`.
        b"execbound-replay-fixture-journal-key-v1",
    }
)

if not all(_HEX.fullmatch(key) for key in PUBLISHED_EXECUTOR_KEYS):
    # `policy.store` writes these into a SQL literal, which is safe only for lowercase hex.
    raise RuntimeError("A published executor key must be lowercase hex")


def hmac_key(key: bytes) -> bytes:
    """The key HMAC-SHA256 actually uses for `key`: hashed when longer than the block, then
    padded with zero bytes to it. Two keys with the same form verify the same signatures."""
    raw = bytes(key)
    if len(raw) > _BLOCK:
        raw = hashlib.sha256(raw).digest()
    return raw.ljust(_BLOCK, b"\x00")


_PUBLISHED_HMAC_KEYS = frozenset(hmac_key(key) for key in PUBLISHED_JOURNAL_KEYS)


def published_executor_key(public_key: str) -> bool:
    """Whether this stored executor public key is one the protocol published."""
    return type(public_key) is str and public_key.lower() in PUBLISHED_EXECUTOR_KEYS


def published_journal_key(key: bytes) -> bool:
    """Whether this HMAC key, in any bytes-like form, is a published key in HMAC's own form."""
    return isinstance(key, bytes | bytearray | memoryview) and hmac_key(key) in _PUBLISHED_HMAC_KEYS
