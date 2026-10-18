# SPDX-License-Identifier: AGPL-3.0-only
"""A tenant's secret at rest: what opens it, and everything that does not.

The value of the envelope is exactly the set of cases below. A ciphertext moved to another
tenant's row, another provider's row or the other column of the same row must not open, or the
additional authenticated data is decoration, and a key that left the ring must not be silently
skipped.
"""

from uuid import uuid4

import pytest

from execbound.envelope import (
    KEY_BYTES,
    EnvelopeError,
    KeyRing,
    seal,
    unseal,
)

SECRET = "a client secret a customer typed"  # nosec B105 - a synthetic value for the tests


def ring(active: str = "k1", *names: str) -> KeyRing:
    keys = {name: bytes([index + 1]) * KEY_BYTES for index, name in enumerate((active, *names))}
    return KeyRing(active, keys)


def test_a_sealed_secret_opens_under_its_own_tenant_provider_and_purpose():
    tenant, provider = uuid4(), uuid4()
    keys = ring()
    ciphertext, key_id = seal(keys, SECRET, tenant, provider, "client_secret")
    assert ciphertext != SECRET and SECRET not in ciphertext
    assert unseal(keys, ciphertext, key_id, tenant, provider, "client_secret") == SECRET


def test_two_seals_of_one_secret_differ():
    """A fresh nonce every time, so equal ciphertexts never say two tenants share a secret."""
    tenant, provider = uuid4(), uuid4()
    keys = ring()
    first, _ = seal(keys, SECRET, tenant, provider, "client_secret")
    second, _ = seal(keys, SECRET, tenant, provider, "client_secret")
    assert first != second


@pytest.mark.parametrize("moved", ["tenant", "provider", "purpose"])
def test_a_ciphertext_moved_to_another_row_or_column_does_not_open(moved):
    tenant, provider = uuid4(), uuid4()
    keys = ring()
    ciphertext, key_id = seal(keys, SECRET, tenant, provider, "client_secret")
    target = {
        "tenant": (uuid4(), provider, "client_secret"),
        "provider": (tenant, uuid4(), "client_secret"),
        "purpose": (tenant, provider, "refresh_token"),
    }[moved]
    with pytest.raises(EnvelopeError) as refused:
        unseal(keys, ciphertext, key_id, *target)
    assert refused.value.code == "INVALID_CIPHERTEXT"


def test_a_key_that_left_the_ring_is_named_rather_than_skipped():
    tenant, provider = uuid4(), uuid4()
    ciphertext, key_id = seal(ring("old"), SECRET, tenant, provider, "client_secret")
    with pytest.raises(EnvelopeError) as refused:
        unseal(ring("new"), ciphertext, key_id, tenant, provider, "client_secret")
    assert refused.value.code == "UNKNOWN_KEY"


def test_a_retired_key_still_opens_what_it_sealed_while_new_rows_use_the_active_one():
    """Rotation is the active key changing; a row is rewritten the next time it is written."""
    tenant, provider = uuid4(), uuid4()
    ciphertext, key_id = seal(ring("old"), SECRET, tenant, provider, "client_secret")
    rotated = KeyRing("new", {**ring("old").keys, "new": b"\x09" * KEY_BYTES})
    assert unseal(rotated, ciphertext, key_id, tenant, provider, "client_secret") == SECRET
    again, new_id = seal(rotated, SECRET, tenant, provider, "client_secret")
    assert new_id == "new"
    assert unseal(rotated, again, new_id, tenant, provider, "client_secret") == SECRET


@pytest.mark.parametrize("value", ["", "zz", "abc", None, b"00", "0" * 54, "0" * 100000, "0" * 57])
def test_a_value_that_is_not_a_ciphertext_is_refused(value):
    tenant, provider = uuid4(), uuid4()
    with pytest.raises(EnvelopeError) as refused:
        unseal(ring(), value, "k1", tenant, provider, "client_secret")
    assert refused.value.code == "INVALID_CIPHERTEXT"


def test_a_tampered_ciphertext_does_not_open():
    tenant, provider = uuid4(), uuid4()
    keys = ring()
    ciphertext, key_id = seal(keys, SECRET, tenant, provider, "client_secret")
    flipped = ciphertext[:-2] + ("00" if ciphertext[-2:] != "00" else "11")
    with pytest.raises(EnvelopeError):
        unseal(keys, flipped, key_id, tenant, provider, "client_secret")


def test_a_purpose_nothing_uses_is_refused():
    tenant, provider = uuid4(), uuid4()
    with pytest.raises(EnvelopeError) as refused:
        seal(ring(), SECRET, tenant, provider, "anything")
    assert refused.value.code == "INVALID_PURPOSE"


@pytest.mark.parametrize("value", ["", None, 1, "x" * 9000])
def test_a_plaintext_that_is_not_one_is_refused(value):
    tenant, provider = uuid4(), uuid4()
    with pytest.raises(EnvelopeError) as refused:
        seal(ring(), value, tenant, provider, "client_secret")
    assert refused.value.code == "INVALID_PLAINTEXT"


@pytest.mark.parametrize(
    "active,keys",
    [
        ("k1", {}),
        ("k1", {"k2": b"\x01" * KEY_BYTES}),
        ("k1", {"k1": b"\x01" * 16}),
        ("k1", {"k1": "not-bytes"}),
        ("", {"": b"\x01" * KEY_BYTES}),
        ("k 1", {"k 1": b"\x01" * KEY_BYTES}),
    ],
)
def test_a_ring_that_could_not_open_a_row_is_refused_at_construction(active, keys):
    with pytest.raises(ValueError):
        KeyRing(active, keys)


def test_the_ring_never_shows_a_key():
    keys = ring("k1", "k2")
    assert "\\x01" not in repr(keys)
    assert repr(keys) == "KeyRing(active_key_id='k1', keys=<2>)"


def test_a_mapping_the_caller_keeps_cannot_change_which_key_opens_a_row():
    supplied = {"k1": b"\x01" * KEY_BYTES}
    keys = KeyRing("k1", supplied)
    supplied["k1"] = b"\x02" * KEY_BYTES
    tenant, provider = uuid4(), uuid4()
    ciphertext, key_id = seal(keys, SECRET, tenant, provider, "client_secret")
    assert unseal(keys, ciphertext, key_id, tenant, provider, "client_secret") == SECRET
